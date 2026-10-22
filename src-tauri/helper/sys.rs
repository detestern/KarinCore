//! Системный слой helper'а: пути, безопасная запись файлов, запуск внешних
//! команд. Всё, что трогает ОС, проходит через `Paths` и трейт `Runner`,
//! поэтому логику операций можно тестировать без root и без реальных `ip`/`iptables`.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct Paths {
    pub conf_dir: PathBuf,
    pub log_dir: PathBuf,
    pub run_dir: PathBuf,
    pub resolv: PathBuf,
    pub proc_dir: PathBuf,
    /// Файл групп: из него берётся gid группы `karincore`, которой разрешено читать журналы.
    pub group_file: PathBuf,
    /// Кто должен владеть каталогами конфигурации (на реальной системе — root, uid 0).
    pub owner_uid: u32,
}

impl Paths {
    pub fn system() -> Paths {
        Paths {
            conf_dir: "/etc/karin-proxy".into(),
            log_dir: "/var/log/karin-proxy".into(),
            run_dir: "/run/karin-proxy".into(),
            resolv: "/etc/resolv.conf".into(),
            proc_dir: "/proc".into(),
            group_file: "/etc/group".into(),
            owner_uid: 0,
        }
    }
    pub fn ovpn_conf(&self) -> PathBuf {
        self.conf_dir.join("openvpn.ovpn")
    }
    pub fn wg_conf(&self) -> PathBuf {
        self.conf_dir.join("wg0.conf")
    }
    pub fn geo_dir(&self) -> PathBuf {
        self.conf_dir.join("geo")
    }
    pub fn resolv_bak(&self) -> PathBuf {
        self.conf_dir.join("resolv.conf.bak")
    }
    pub fn err_log(&self) -> PathBuf {
        self.log_dir.join("error.log")
    }
    pub fn acc_log(&self) -> PathBuf {
        self.log_dir.join("access.log")
    }
    pub fn ks_state(&self) -> PathBuf {
        self.run_dir.join("killswitch_ip")
    }
    pub fn lock_file(&self) -> PathBuf {
        self.run_dir.join("helper.lock")
    }
}

/// Каталог должен существовать, быть настоящим каталогом (не symlink), принадлежать
/// `owner_uid` и не быть доступным на запись группе/всем.
pub fn check_dir(dir: &Path, owner_uid: u32) -> Result<(), String> {
    let md = fs::symlink_metadata(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    if !md.is_dir() {
        return Err(format!("{} не является каталогом", dir.display()));
    }
    if md.uid() != owner_uid {
        return Err(format!(
            "{}: неверный владелец каталога (после обновления со старой версии выполните: sudo chown -R root:root {})",
            dir.display(),
            dir.display()
        ));
    }
    if md.mode() & 0o022 != 0 {
        return Err(format!("{}: каталог доступен на запись группе или всем", dir.display()));
    }
    Ok(())
}

pub fn ensure_dir(dir: &Path, mode: u32, owner_uid: u32) -> Result<(), String> {
    if fs::symlink_metadata(dir).is_err() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).map_err(|e| format!("{}: {}", dir.display(), e))?;
    }
    check_dir(dir, owner_uid)
}

/// Атомарная запись: временный файл создаётся `O_EXCL` в том же (root-owned)
/// каталоге, затем `rename`. Если на месте цели лежит symlink, он будет заменён,
/// а не пройден.
pub fn write_atomic(dir: &Path, name: &str, data: &[u8], mode: u32, owner_uid: u32) -> Result<(), String> {
    check_dir(dir, owner_uid)?;
    let tmp = dir.join(format!(".{}.{}.tmp", name, std::process::id()));
    let _ = fs::remove_file(&tmp);
    let res = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        fs::rename(&tmp, dir.join(name))
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(format!("Не удалось записать {}: {}", name, e));
    }
    Ok(())
}

/// gid группы по имени из файла групп (`name:x:gid:members`).
pub fn lookup_gid(group_file: &Path, name: &str) -> Option<u32> {
    let text = fs::read_to_string(group_file).ok()?;
    text.lines().find_map(|line| {
        let mut parts = line.split(':');
        if parts.next()? != name {
            return None;
        }
        parts.next()?;
        parts.next()?.parse().ok()
    })
}

/// Журналы содержат адреса сайтов, поэтому читать их может только root и группа `karincore`:
/// каталог 0750, файлы 0640. Права и группа выставляются при каждом вызове, так что журналы,
/// созданные старыми версиями с правами 0644, исправляются при первом же подключении.
/// Если группы `karincore` нет, журналы остаются доступны только root.
pub fn secure_log_dir(paths: &Paths) -> Result<(), String> {
    ensure_dir(&paths.log_dir, 0o750, paths.owner_uid)?;
    let dir = &paths.log_dir;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o750)).map_err(|e| format!("{}: {}", dir.display(), e))?;
    let gid = lookup_gid(&paths.group_file, "karincore");
    std::os::unix::fs::chown(dir, Some(paths.owner_uid), gid).map_err(|e| format!("{}: {}", dir.display(), e))
}

pub fn secure_log_file(paths: &Paths, file: &Path) {
    let _ = fs::set_permissions(file, fs::Permissions::from_mode(0o640));
    let _ = std::os::unix::fs::chown(file, None, lookup_gid(&paths.group_file, "karincore"));
}

pub fn append_log(path: &Path, text: &str) {
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).mode(0o640).open(path) {
        let _ = f.write_all(text.as_bytes());
        if !text.ends_with('\n') {
            let _ = f.write_all(b"\n");
        }
    }
}

pub struct CmdResult {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

pub trait Runner {
    fn run(&self, tool: &str, args: &[&str]) -> CmdResult;
    /// Запускает процесс в отдельной группе, вывод дописывается в `log`. Возвращает pid.
    fn spawn_detached(&self, tool: &str, args: &[&str], log: &Path) -> Result<u32, String>;
    fn signal(&self, pid: u32, sig: i32);
}

pub struct SysRunner;

const TOOL_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

/// Ищет инструмент в стандартных каталогах и принимает его только если файл
/// принадлежит root и не доступен на запись группе/всем. PATH из окружения не используется.
pub fn resolve_tool(name: &str) -> Option<PathBuf> {
    for d in TOOL_DIRS {
        let p = Path::new(d).join(name);
        if let Ok(md) = fs::metadata(&p) {
            if md.is_file() && md.uid() == 0 && md.mode() & 0o022 == 0 {
                return Some(p);
            }
        }
    }
    None
}

fn base_command(path: &Path) -> Command {
    let mut c = Command::new(path);
    c.env_clear().env("PATH", "/usr/bin:/usr/sbin:/bin:/sbin").env("LC_ALL", "C").env("LANG", "C");
    c
}

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

impl Runner for SysRunner {
    fn run(&self, tool: &str, args: &[&str]) -> CmdResult {
        let path = match resolve_tool(tool) {
            Some(p) => p,
            None => {
                return CmdResult { ok: false, stdout: String::new(), stderr: format!("не найден доверенный бинарник: {}", tool) }
            }
        };
        match base_command(&path).args(args).stdin(Stdio::null()).output() {
            Ok(o) => CmdResult {
                ok: o.status.success(),
                stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            },
            Err(e) => CmdResult { ok: false, stdout: String::new(), stderr: e.to_string() },
        }
    }

    fn spawn_detached(&self, tool: &str, args: &[&str], log: &Path) -> Result<u32, String> {
        let path = resolve_tool(tool).ok_or_else(|| format!("не найден доверенный бинарник: {}", tool))?;
        let out = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(log)
            .map_err(|e| format!("{}: {}", log.display(), e))?;
        let err = out.try_clone().map_err(|e| e.to_string())?;
        let child = base_command(&path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .process_group(0)
            .spawn()
            .map_err(|e| format!("Не удалось запустить {}: {}", tool, e))?;
        Ok(child.id())
    }

    fn signal(&self, pid: u32, sig: i32) {
        // SAFETY: простой системный вызов kill(2) с числовыми аргументами.
        unsafe {
            kill(pid as i32, sig);
        }
    }
}

#[cfg(test)]
pub mod testutil {
    use super::*;
    use std::cell::RefCell;

    pub struct Fake {
        pub calls: RefCell<Vec<String>>,
        pub fail_on: RefCell<Vec<String>>,
        pub outputs: RefCell<Vec<(String, String)>>,
        pub signals: RefCell<Vec<(u32, i32)>>,
    }

    impl Fake {
        pub fn new() -> Fake {
            Fake {
                calls: RefCell::new(vec![]),
                fail_on: RefCell::new(vec![]),
                outputs: RefCell::new(vec![]),
                signals: RefCell::new(vec![]),
            }
        }
        pub fn log(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
        pub fn fail(&self, prefix: &str) {
            self.fail_on.borrow_mut().push(prefix.to_string());
        }
        pub fn output(&self, prefix: &str, stdout: &str) {
            self.outputs.borrow_mut().push((prefix.to_string(), stdout.to_string()));
        }
    }

    impl Runner for Fake {
        fn run(&self, tool: &str, args: &[&str]) -> CmdResult {
            let line = format!("{} {}", tool, args.join(" "));
            self.calls.borrow_mut().push(line.clone());
            let failed = self.fail_on.borrow().iter().any(|p| line.starts_with(p.as_str()));
            let stdout = self
                .outputs
                .borrow()
                .iter()
                .find(|(p, _)| line.starts_with(p.as_str()))
                .map(|(_, o)| o.clone())
                .unwrap_or_default();
            CmdResult { ok: !failed, stdout, stderr: if failed { "fake failure".into() } else { String::new() } }
        }
        fn spawn_detached(&self, tool: &str, args: &[&str], _log: &Path) -> Result<u32, String> {
            self.calls.borrow_mut().push(format!("SPAWN {} {}", tool, args.join(" ")));
            Ok(4242)
        }
        fn signal(&self, pid: u32, sig: i32) {
            self.signals.borrow_mut().push((pid, sig));
        }
    }

    pub fn temp_paths(tag: &str) -> Paths {
        let root = std::env::temp_dir().join(format!("karin-helper-test-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        let p = Paths {
            conf_dir: root.join("etc"),
            log_dir: root.join("log"),
            run_dir: root.join("run"),
            resolv: root.join("resolv.conf"),
            proc_dir: root.join("proc"),
            group_file: root.join("group"),
            owner_uid: uid,
        };
        // Своя группа «karincore» с gid текущего пользователя: chown на неё разрешён без root.
        let gid = fs::metadata(&root).unwrap().gid();
        fs::write(&p.group_file, format!("root:x:0:\nkarincore:x:{}:tester\n", gid)).unwrap();
        fs::create_dir_all(&p.conf_dir).unwrap();
        fs::set_permissions(&p.conf_dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(&p.proc_dir).unwrap();
        p
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn atomic_write_sets_mode_and_content() {
        let p = temp_paths("atomic");
        write_atomic(&p.conf_dir, "x.conf", b"hello", 0o600, p.owner_uid).unwrap();
        let md = fs::metadata(p.conf_dir.join("x.conf")).unwrap();
        assert_eq!(md.mode() & 0o777, 0o600);
        assert_eq!(fs::read(p.conf_dir.join("x.conf")).unwrap(), b"hello");
        // перезапись
        write_atomic(&p.conf_dir, "x.conf", b"bye", 0o600, p.owner_uid).unwrap();
        assert_eq!(fs::read(p.conf_dir.join("x.conf")).unwrap(), b"bye");
        // временных файлов не осталось
        let leftovers: Vec<_> = fs::read_dir(&p.conf_dir).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().ends_with(".tmp")).collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn atomic_write_replaces_symlink_instead_of_following() {
        let p = temp_paths("symlink");
        let victim = p.conf_dir.join("victim.txt");
        fs::write(&victim, "SECRET").unwrap();
        std::os::unix::fs::symlink(&victim, p.conf_dir.join("config.json")).unwrap();
        write_atomic(&p.conf_dir, "config.json", b"new", 0o600, p.owner_uid).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "SECRET");
        assert_eq!(fs::read(p.conf_dir.join("config.json")).unwrap(), b"new");
    }

    #[test]
    fn check_dir_rejects_group_writable_symlink_and_wrong_owner() {
        let p = temp_paths("checkdir");
        let d = p.conf_dir.join("w");
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(check_dir(&d, p.owner_uid).is_err());
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_dir(&d, p.owner_uid).is_ok());
        assert!(check_dir(&d, p.owner_uid.wrapping_add(1)).is_err());
        let link = p.conf_dir.join("lnk");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(check_dir(&link, p.owner_uid).is_err());
        assert!(check_dir(&p.conf_dir.join("nope"), p.owner_uid).is_err());
    }

    #[test]
    fn ensure_dir_creates_with_mode() {
        let p = temp_paths("ensure");
        let d = p.log_dir.clone();
        ensure_dir(&d, 0o755, p.owner_uid).unwrap();
        assert_eq!(fs::metadata(&d).unwrap().mode() & 0o777, 0o755);
    }

    #[test]
    fn lookup_gid_reads_the_group_file() {
        let p = temp_paths("gid");
        fs::write(&p.group_file, "root:x:0:\nkarincore:x:987:alice,bob\nkarincore2:x:5:\n").unwrap();
        assert_eq!(lookup_gid(&p.group_file, "karincore"), Some(987));
        assert_eq!(lookup_gid(&p.group_file, "karin"), None);
        assert_eq!(lookup_gid(&p.group_file, "nobody"), None);
        assert_eq!(lookup_gid(&p.conf_dir.join("missing"), "karincore"), None);
    }

    #[test]
    fn resolve_tool_ignores_missing() {
        assert!(resolve_tool("definitely-not-a-real-tool-xyz").is_none());
    }
}
