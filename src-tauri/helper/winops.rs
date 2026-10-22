//! Логика службы KarinCore для Windows: какие операции протокола `KARIN-HELPER/1`
//! она выполняет и как. Работа с ОС (права на каталоги, запуск Xray) вынесена в
//! трейт [`Os`], поэтому всё здесь проверяется юнит-тестами и на Linux, с подделкой.
//!
//! Граница привилегий та же, что на Linux: служба работает от SYSTEM, принимает
//! запросы только через named pipe и сама проверяет всё, что пришло от GUI.

// На Linux модуль собирается только для тестов.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::proto::Request;
use crate::xray;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const SERVICE_NAME: &str = "KarinCore";
pub const PIPE_NAME: &str = r"\\.\pipe\karincore-helper";

/// Больше этого служба не читает из пайпа: самый большой допустимый запрос — core-config (1 МиБ).
pub const MAX_MESSAGE: usize = crate::proto::MAX_HEADER + 1024 * 1024 + 1;

const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
const CONSOLE_TAIL_LINES: usize = 30;

/// Каталоги службы. `data` — `%ProgramData%\KarinCore`, `install` — каталог установки
/// (Program Files), где лежат служба и `core\xray.exe`.
pub struct Paths {
    pub data: PathBuf,
    pub install: PathBuf,
}

impl Paths {
    pub fn config_dir(&self) -> PathBuf {
        self.data.join("config")
    }
    pub fn log_dir(&self) -> PathBuf {
        self.data.join("logs")
    }
    pub fn config_file(&self) -> PathBuf {
        self.config_dir().join("config.json")
    }
    pub fn err_log(&self) -> PathBuf {
        self.log_dir().join("error.log")
    }
    pub fn acc_log(&self) -> PathBuf {
        self.log_dir().join("access.log")
    }
    /// Вывод самого процесса Xray (ошибки разбора конфига попадают сюда, а не в error.log).
    pub fn console_log(&self) -> PathBuf {
        self.log_dir().join("core.log")
    }
    pub fn core_dir(&self) -> PathBuf {
        self.install.join("core")
    }
    pub fn xray_exe(&self) -> PathBuf {
        self.core_dir().join("xray.exe")
    }
}

/// Операции ОС, которые нужны службе. На Windows — `win::WinOs`, в тестах — подделка.
pub trait Os {
    /// Создаёт каталог, если его нет, и ставит ему защищённый DACL: полный доступ у SYSTEM
    /// и администраторов, а `reader` (SID пользователя), если указан, получает только чтение.
    fn secure_dir(&self, dir: &Path, reader: Option<&str>) -> Result<(), String>;
    /// То же для файла.
    fn secure_file(&self, file: &Path, reader: Option<&str>) -> Result<(), String>;
    /// Запускает `xray.exe run -c config`, вывод процесса пишет в `console_log`.
    fn core_start(&self, paths: &Paths) -> Result<(), String>;
    fn core_stop(&self);
    fn core_running(&self) -> bool;
    fn sleep_ms(&self, ms: u64);
}

/// Состояние службы между запросами.
#[derive(Default)]
pub struct State {
    /// SID пользователя, который последним настроил ядро: только он читает логи
    /// и только он управляет ядром, пока оно работает.
    pub owner: Option<String>,
    /// GUI закрылся (`stop-services`): служба останавливает ядро и завершается.
    pub stop_requested: bool,
}

pub struct Ctx<'a> {
    pub paths: &'a Paths,
    pub os: &'a dyn Os,
    /// Сколько ждать после запуска Xray, прежде чем проверить, что процесс жив.
    pub settle_ms: u64,
}

type Res = Result<String, String>;

/// SID вида `S-1-5-21-…`. Попадает в строку SDDL, поэтому формат проверяется строго.
pub fn valid_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-") else { return false };
    sid.len() <= 184
        && !rest.is_empty()
        && rest.split('-').all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// DACL каталога или файла: SYSTEM и администраторы — полный доступ, `reader` — чтение.
/// Флаги наследования нужны каталогам, чтобы файлы внутри получили те же права.
pub fn dacl_sddl(reader: Option<&str>, is_dir: bool) -> Result<String, String> {
    let inherit = if is_dir { "OICI" } else { "" };
    let mut s = format!("D:P(A;{i};FA;;;SY)(A;{i};FA;;;BA)", i = inherit);
    if let Some(sid) = reader {
        if !valid_sid(sid) {
            return Err("некорректный SID пользователя".into());
        }
        s.push_str(&format!("(A;{};FR;;;{})", inherit, sid));
    }
    Ok(s)
}

/// Операции, которые на Windows пока означают «делать нечего»: GUI вызывает их при отключении.
const NOOP_OPS: &[&str] = &["ks-off", "dns-restore", "route-cleanup", "ovpn-stop", "wg-down"];

/// Операции, которые изменяют состояние ядра: их выполняет только владелец работающего ядра.
const OWNER_OPS: &[&str] = &["core-config", "core-restart", "core-stop", "logs-clear", "teardown", "stop-services"];

pub fn dispatch(ctx: &Ctx, state: &mut State, req: &Request, caller: &str) -> Res {
    if req.op == "version" {
        return Ok(format!("karincore-service {} proto 1", env!("CARGO_PKG_VERSION")));
    }
    if !valid_sid(caller) {
        return Err("не удалось определить пользователя, который обратился к службе".into());
    }
    if OWNER_OPS.contains(&req.op.as_str()) {
        if let Some(owner) = &state.owner {
            if owner != caller && ctx.os.core_running() {
                return Err("KarinCore сейчас подключён другим пользователем этого компьютера.".into());
            }
        }
    }
    match req.op.as_str() {
        "core-config" => core_config(ctx, state, req, caller),
        "core-restart" => core_restart(ctx, state, caller),
        "core-stop" => {
            ctx.os.core_stop();
            Ok(String::new())
        }
        "logs-clear" => logs_clear(ctx, state),
        "teardown" => {
            ctx.os.core_stop();
            Ok(String::new())
        }
        "stop-services" => {
            ctx.os.core_stop();
            state.stop_requested = true;
            Ok(String::new())
        }
        op if NOOP_OPS.contains(&op) => Ok(String::new()),
        op => Err(format!("Операция {} пока не поддерживается в Windows-версии KarinCore.", op)),
    }
}

fn utf8_body(req: &Request) -> Result<String, String> {
    String::from_utf8(req.body.clone()).map_err(|_| "конфигурация Xray: тело запроса не является UTF-8".to_string())
}

/// Каталог данных, каталог конфигурации и каталог логов с правами; логи читает `reader`.
fn prepare_dirs(ctx: &Ctx, reader: Option<&str>) -> Result<(), String> {
    ctx.os.secure_dir(&ctx.paths.data, None)?;
    ctx.os.secure_dir(&ctx.paths.config_dir(), None)?;
    ctx.os.secure_dir(&ctx.paths.log_dir(), reader)?;
    Ok(())
}

fn ensure_log_files(ctx: &Ctx, reader: Option<&str>) -> Result<(), String> {
    for f in [ctx.paths.err_log(), ctx.paths.acc_log(), ctx.paths.console_log()] {
        if fs::metadata(&f).map(|m| m.len() > LOG_ROTATE_BYTES).unwrap_or(false) {
            let _ = fs::write(&f, "");
        }
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&f)
            .map_err(|e| format!("{}: {}", f.display(), e))?;
        ctx.os.secure_file(&f, reader)?;
    }
    Ok(())
}

fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> Result<(), String> {
    let tmp = dir.join(format!(".{}.{}.tmp", name, std::process::id()));
    let _ = fs::remove_file(&tmp);
    let res = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        // std::fs::rename на Windows заменяет существующий файл (MoveFileEx + REPLACE_EXISTING)
        fs::rename(&tmp, dir.join(name))
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(format!("Не удалось записать {}: {}", name, e));
    }
    Ok(())
}

fn core_config(ctx: &Ctx, state: &mut State, req: &Request, caller: &str) -> Res {
    let body = utf8_body(req)?;
    prepare_dirs(ctx, Some(caller))?;
    ensure_log_files(ctx, Some(caller))?;
    let err = ctx.paths.err_log();
    let acc = ctx.paths.acc_log();
    let logs = xray::LogPaths {
        access: acc.to_str().ok_or("путь лога не UTF-8")?,
        error: err.to_str().ok_or("путь лога не UTF-8")?,
    };
    let canonical = xray::validate(&body, &logs)?;
    // В конфиге ключи серверов и токен локального прокси: каталог доступен только SYSTEM и администраторам.
    write_atomic(&ctx.paths.config_dir(), "config.json", canonical.as_bytes())?;
    ctx.os.secure_file(&ctx.paths.config_file(), None)?;
    state.owner = Some(caller.to_string());
    Ok(String::new())
}

fn tail(path: &Path, lines: usize) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

fn core_restart(ctx: &Ctx, state: &State, caller: &str) -> Res {
    ctx.os.core_stop();
    if state.owner.as_deref() != Some(caller) || !ctx.paths.config_file().exists() {
        return Err("Сначала нужно передать службе конфигурацию ядра.".into());
    }
    if !ctx.paths.xray_exe().exists() {
        return Err(format!("Не найден {}. Переустановите KarinCore.", ctx.paths.xray_exe().display()));
    }
    prepare_dirs(ctx, Some(caller))?;
    ensure_log_files(ctx, Some(caller))?;
    let _ = fs::write(ctx.paths.console_log(), "");
    ctx.os.core_start(ctx.paths)?;
    ctx.os.sleep_ms(ctx.settle_ms);
    if !ctx.os.core_running() {
        let log = tail(&ctx.paths.console_log(), CONSOLE_TAIL_LINES);
        return Err(if log.is_empty() { "Ядро Xray сразу завершилось.".to_string() } else { log });
    }
    Ok(String::new())
}

fn logs_clear(ctx: &Ctx, state: &State) -> Res {
    let reader = state.owner.as_deref();
    for f in [ctx.paths.err_log(), ctx.paths.acc_log(), ctx.paths.console_log()] {
        if f.exists() {
            fs::write(&f, "").map_err(|e| format!("{}: {}", f.display(), e))?;
            ctx.os.secure_file(&f, reader)?;
        }
    }
    Ok(String::new())
}

/// Ответ службы в том же формате, что у helper'а на Linux: `OK`/`ERR` и сообщение.
pub fn reply(res: &Res) -> Vec<u8> {
    let (head, msg) = match res {
        Ok(m) => ("OK", m.as_str()),
        Err(m) => ("ERR", m.as_str()),
    };
    let mut out = format!("{}\n", head);
    if !msg.is_empty() {
        out.push_str(msg);
        out.push('\n');
    }
    out.into_bytes()
}

/// Обрабатывает одно сообщение из пайпа целиком: разбор, выполнение, ответ.
pub fn handle_message(ctx: &Ctx, state: &mut State, msg: &[u8], caller: &str) -> Vec<u8> {
    let res = crate::proto::read_request(&mut &msg[..]).and_then(|req| dispatch(ctx, state, &req, caller));
    reply(&res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const ME: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    const OTHER: &str = "S-1-5-21-1111111111-2222222222-3333333333-1002";

    #[derive(Default)]
    struct Fake {
        log: RefCell<Vec<String>>,
        running: Cell<bool>,
        start_fails: Cell<bool>,
        dies_at_start: Cell<bool>,
    }

    impl Os for Fake {
        fn secure_dir(&self, dir: &Path, reader: Option<&str>) -> Result<(), String> {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            self.log.borrow_mut().push(format!("dir {} {}", dir.file_name().unwrap().to_string_lossy(), reader.unwrap_or("-")));
            Ok(())
        }
        fn secure_file(&self, file: &Path, reader: Option<&str>) -> Result<(), String> {
            self.log.borrow_mut().push(format!("file {} {}", file.file_name().unwrap().to_string_lossy(), reader.unwrap_or("-")));
            Ok(())
        }
        fn core_start(&self, paths: &Paths) -> Result<(), String> {
            self.log.borrow_mut().push("start".into());
            if self.start_fails.get() {
                return Err("CreateProcess failed".into());
            }
            if self.dies_at_start.get() {
                fs::write(paths.console_log(), "Failed to start: bad config\n").unwrap();
            } else {
                self.running.set(true);
            }
            Ok(())
        }
        fn core_stop(&self) {
            self.log.borrow_mut().push("stop".into());
            self.running.set(false);
        }
        fn core_running(&self) -> bool {
            self.running.get()
        }
        fn sleep_ms(&self, _ms: u64) {}
    }

    fn paths(tag: &str) -> Paths {
        let base = std::env::temp_dir().join(format!("karin-winops-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let install = base.join("install");
        fs::create_dir_all(install.join("core")).unwrap();
        fs::write(install.join("core").join("xray.exe"), b"MZ").unwrap();
        Paths { data: base.join("data"), install }
    }

    fn rq(op: &str, body: &[u8]) -> Request {
        Request { op: op.into(), params: vec![], body: body.to_vec() }
    }

    const CONFIG: &str = r#"{"log":{"loglevel":"debug","access":"C:\\evil.log","error":"C:\\evil.log"},
        "inbounds":[{"port":2080,"listen":"127.0.0.1","protocol":"mixed","settings":{"accounts":[{"user":"karin","pass":"x"}]}}],
        "outbounds":[{"tag":"direct","protocol":"freedom"}]}"#;

    #[test]
    fn sid_format_is_strict() {
        assert!(valid_sid(ME));
        assert!(valid_sid("S-1-5-18"));
        for bad in ["", "S-1-", "S-1-5-", "S-1-5--18", "S-1-5-18)(A;;FA;;;WD", "s-1-5-18", "S-1-5-x", "S-1-5-12345678901"] {
            assert!(!valid_sid(bad), "{:?}", bad);
        }
    }

    #[test]
    fn dacl_strings() {
        assert_eq!(dacl_sddl(None, true).unwrap(), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert_eq!(
            dacl_sddl(Some(ME), false).unwrap(),
            format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{})", ME)
        );
        assert!(dacl_sddl(Some("S-1-1-0)(A;;FA;;;WD"), true).is_err());
    }

    #[test]
    fn version_needs_no_caller() {
        let p = paths("ver");
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let r = dispatch(&ctx, &mut State::default(), &rq("version", b""), "").unwrap();
        assert!(r.starts_with("karincore-service "));
    }

    #[test]
    fn core_config_validates_writes_and_gives_logs_to_caller() {
        let p = paths("cfg");
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        let written = fs::read_to_string(p.config_file()).unwrap();
        assert!(!written.contains("evil"), "пути логов должны быть подменены");
        assert!(written.contains("error.log"));
        assert_eq!(st.owner.as_deref(), Some(ME));
        let log = os.log.borrow();
        assert!(log.contains(&format!("dir logs {}", ME)));
        assert!(log.contains(&"dir config -".to_string()));
        assert!(log.contains(&"file config.json -".to_string()));
        assert!(log.contains(&format!("file error.log {}", ME)));
    }

    #[test]
    fn hostile_config_is_rejected_and_old_one_kept() {
        let p = paths("hostile");
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        let before = fs::read_to_string(p.config_file()).unwrap();
        let bad = CONFIG.replace("127.0.0.1", "0.0.0.0");
        assert!(dispatch(&ctx, &mut st, &rq("core-config", bad.as_bytes()), ME).is_err());
        assert_eq!(fs::read_to_string(p.config_file()).unwrap(), before);
    }

    #[test]
    fn restart_needs_config_from_the_same_user() {
        let p = paths("order");
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        assert!(dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).is_err());
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        assert!(dispatch(&ctx, &mut st, &rq("core-restart", b""), OTHER).is_err());
        dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).unwrap();
        assert!(os.running.get());
    }

    #[test]
    fn other_user_cannot_touch_a_running_core() {
        let p = paths("other");
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).unwrap();
        for op in OWNER_OPS {
            let body: &[u8] = if *op == "core-config" { CONFIG.as_bytes() } else { b"" };
            assert!(dispatch(&ctx, &mut st, &rq(op, body), OTHER).is_err(), "{}", op);
        }
        assert!(os.running.get());
        // после отключения владельцем ядро может настроить другой пользователь
        dispatch(&ctx, &mut st, &rq("core-stop", b""), ME).unwrap();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), OTHER).unwrap();
        assert_eq!(st.owner.as_deref(), Some(OTHER));
    }

    #[test]
    fn core_that_dies_reports_its_console_output() {
        let p = paths("dies");
        let os = Fake::default();
        os.dies_at_start.set(true);
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        let e = dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).unwrap_err();
        assert!(e.contains("bad config"), "{}", e);
    }

    #[test]
    fn missing_xray_is_reported() {
        let p = paths("noxray");
        fs::remove_file(p.xray_exe()).unwrap();
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        let e = dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).unwrap_err();
        assert!(e.contains("xray.exe"));
        assert!(!os.log.borrow().contains(&"start".to_string()));
    }

    #[test]
    fn start_failure_is_returned() {
        let p = paths("startfail");
        let os = Fake::default();
        os.start_fails.set(true);
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        assert_eq!(dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).unwrap_err(), "CreateProcess failed");
    }

    #[test]
    fn teardown_and_stop_services() {
        let p = paths("stop");
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).unwrap();
        dispatch(&ctx, &mut st, &rq("teardown", b""), ME).unwrap();
        assert!(!os.running.get());
        assert!(!st.stop_requested);
        dispatch(&ctx, &mut st, &rq("stop-services", b""), ME).unwrap();
        assert!(st.stop_requested);
    }

    #[test]
    fn noop_and_unsupported_ops() {
        let p = paths("ops");
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        for op in NOOP_OPS {
            assert_eq!(dispatch(&ctx, &mut st, &rq(op, b""), ME), Ok(String::new()));
        }
        for op in ["ks-on", "bypass", "dns-vpn", "geo-install", "wg-up", "ovpn-start", "route-fwmark"] {
            let e = dispatch(&ctx, &mut st, &rq(op, b""), ME).unwrap_err();
            assert!(e.contains("Windows"), "{}", op);
        }
    }

    #[test]
    fn caller_without_sid_is_rejected() {
        let p = paths("nosid");
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        assert!(dispatch(&ctx, &mut State::default(), &rq("teardown", b""), "").is_err());
    }

    #[test]
    fn logs_clear_keeps_reader() {
        let p = paths("clear");
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        fs::write(p.err_log(), "line\n").unwrap();
        os.log.borrow_mut().clear();
        dispatch(&ctx, &mut st, &rq("logs-clear", b""), ME).unwrap();
        assert_eq!(fs::read_to_string(p.err_log()).unwrap(), "");
        assert!(os.log.borrow().contains(&format!("file error.log {}", ME)));
    }

    #[test]
    fn message_roundtrip_uses_the_shared_protocol() {
        let p = paths("msg");
        let os = Fake::default();
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        let ok = handle_message(&ctx, &mut st, b"KARIN-HELPER/1 version\n", ME);
        assert!(ok.starts_with(b"OK\nkarincore-service "));
        let bad = handle_message(&ctx, &mut st, b"KARIN-HELPER/1 rm-rf\n", ME);
        assert!(bad.starts_with(b"ERR\n"));
        let trailing = handle_message(&ctx, &mut st, b"KARIN-HELPER/1 version\nextra", ME);
        assert!(trailing.starts_with(b"ERR\n"));
        assert_eq!(reply(&Ok(String::new())), b"OK\n");
    }
}
