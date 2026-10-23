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
    /// Включает Kill Switch по плану [`kill_switch_plan`] одной транзакцией WFP (всё или ничего).
    fn ks_on(&self, paths: &Paths) -> Result<(), String>;
    /// Снимает фильтры Kill Switch; если их нет, это не ошибка.
    fn ks_off(&self) -> Result<(), String>;
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

/// Операции, которые на Windows означают «делать нечего»: GUI вызывает их при отключении,
/// а маршруты и DNS на Windows живут и умирают вместе с процессом Xray.
const NOOP_OPS: &[&str] = &["dns-restore", "route-cleanup", "ovpn-stop", "wg-down"];

/// Операции, которые изменяют состояние ядра или защиты: пока ядро работает,
/// их выполняет только тот пользователь, который его настроил.
const OWNER_OPS: &[&str] =
    &["core-config", "core-restart", "core-stop", "logs-clear", "teardown", "stop-services", "ks-on", "ks-off"];

/// Имя TUN-адаптера (как в GUI, platform::WIN_TUN_NAME): Kill Switch пропускает трафик через него.
pub const TUN_IFACE: &str = "karincore";
const KS_MAX_SERVERS: usize = 16;

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
            // Как на Linux: отключение снимает и Kill Switch. Ошибку не прячем.
            let ks = ctx.os.ks_off();
            ctx.os.core_stop();
            ks.map(|_| String::new())
        }
        "ks-on" => ks_on(ctx, req),
        "ks-off" => ctx.os.ks_off().map(|_| String::new()),
        "stop-services" => {
            ctx.os.core_stop();
            state.stop_requested = true;
            Ok(String::new())
        }
        op if NOOP_OPS.contains(&op) => Ok(String::new()),
        op => Err(format!("Операция {} пока не поддерживается в Windows-версии KarinCore.", op)),
    }
}

/// Параметры ks-on те же, что у Linux-helper'а: адреса сервера (проверяются, но правил для них
/// не нужно — соединения с сервером открывает xray.exe, а он разрешён целиком) и интерфейс.
fn ks_on(ctx: &Ctx, req: &Request) -> Res {
    let raw = req.param("server_ip").ok_or("не указан ни один адрес сервера")?;
    let ips: Vec<&str> = raw.split(',').filter(|s| !s.is_empty()).collect();
    if ips.is_empty() || ips.len() > KS_MAX_SERVERS {
        return Err(format!("нужно от 1 до {} адресов сервера", KS_MAX_SERVERS));
    }
    for ip in &ips {
        ip.parse::<std::net::IpAddr>().map_err(|_| format!("некорректный IP-адрес: {}", ip))?;
    }
    if req.param("iface") != Some(TUN_IFACE) {
        return Err(format!("Kill Switch на Windows работает только с адаптером {}", TUN_IFACE));
    }
    if !ctx.os.core_running() {
        return Err("ядро не запущено: Kill Switch не на что опирать".into());
    }
    ctx.os.ks_on(ctx.paths)?;
    Ok(String::new())
}

// ---------------------------------------------------------------- Kill Switch: план фильтров

/// Слой WFP, на котором стоит фильтр: исходящие соединения (CONNECT) и входящие (RECV_ACCEPT).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KsLayer {
    ConnectV4,
    ConnectV6,
    AcceptV4,
    AcceptV6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KsCond {
    /// Трафик внутри компьютера (127.0.0.1, ::1).
    Loopback,
    /// Любой трафик процесса xray.exe из каталога установки (аналог метки 0xff на Linux).
    CoreApp,
    /// Трафик через адаптер KarinCore.
    TunInterface,
    Protocol(u8),
    /// Для ICMP это тип сообщения (так устроены поля WFP).
    LocalPort(u16),
    RemotePort(u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KsFilter {
    pub layer: KsLayer,
    pub permit: bool,
    /// Вес внутри нашего подслоя: решает самый тяжёлый подходящий фильтр.
    pub weight: u8,
    pub conds: Vec<KsCond>,
}

pub const KS_LAYERS: [KsLayer; 4] = [KsLayer::ConnectV4, KsLayer::ConnectV6, KsLayer::AcceptV4, KsLayer::AcceptV6];
/// Столько ключей фильтров зарезервировано (снимаются все, даже если план стал короче).
pub const KS_MAX_FILTERS: usize = 64;

/// Что пропускает Kill Switch. Как nftables-таблица на Linux: loopback, туннель и само ядро;
/// всё остальное — блокировать. Плюс то, без чего Windows теряет сеть на физическом адаптере:
/// DHCP (продление адреса) и обнаружение соседей IPv6. Локальная сеть блокируется, как на Linux.
pub fn kill_switch_plan() -> Vec<KsFilter> {
    use KsCond::*;
    let mut v = Vec::new();
    let permit = |layer, weight, conds: Vec<KsCond>| KsFilter { layer, permit: true, weight, conds };
    for layer in KS_LAYERS {
        v.push(permit(layer, 15, vec![Loopback]));
        v.push(permit(layer, 15, vec![CoreApp]));
        v.push(permit(layer, 14, vec![TunInterface]));
        let v6 = matches!(layer, KsLayer::ConnectV6 | KsLayer::AcceptV6);
        if v6 {
            v.push(permit(layer, 12, vec![Protocol(17), LocalPort(546), RemotePort(547)]));
            // Router/Neighbor Solicitation/Advertisement и Redirect
            for icmp_type in 133..=137 {
                v.push(permit(layer, 12, vec![Protocol(58), LocalPort(icmp_type)]));
            }
        } else {
            v.push(permit(layer, 12, vec![Protocol(17), LocalPort(68), RemotePort(67)]));
        }
        v.push(KsFilter { layer, permit: false, weight: 0, conds: vec![] });
    }
    v
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
        ks: Cell<bool>,
        ks_fails: Cell<bool>,
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
        fn ks_on(&self, _paths: &Paths) -> Result<(), String> {
            self.log.borrow_mut().push("ks-on".into());
            if self.ks_fails.get() {
                return Err("FwpmTransactionCommit0: 0x80320009".into());
            }
            self.ks.set(true);
            Ok(())
        }
        fn ks_off(&self) -> Result<(), String> {
            self.log.borrow_mut().push("ks-off".into());
            self.ks.set(false);
            Ok(())
        }
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

    fn ks_rq(server: &str, iface: &str) -> Request {
        Request {
            op: "ks-on".into(),
            params: vec![("server_ip".into(), server.into()), ("iface".into(), iface.into())],
            body: vec![],
        }
    }

    fn running(tag: &str) -> (Paths, Fake) {
        let p = paths(tag);
        let os = Fake::default();
        (p, os)
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
        for op in ["bypass", "dns-vpn", "geo-install", "wg-up", "ovpn-start", "route-fwmark"] {
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

    #[test]
    fn kill_switch_needs_running_core_and_valid_params() {
        let (p, os) = running("ks");
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        // ядро ещё не запущено
        assert!(dispatch(&ctx, &mut st, &ks_rq("203.0.113.5", TUN_IFACE), ME).is_err());
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).unwrap();
        for (server, iface) in [("", TUN_IFACE), ("example.com", TUN_IFACE), ("203.0.113.5", "tun0"), ("1.2.3.4,evil", TUN_IFACE)] {
            assert!(dispatch(&ctx, &mut st, &ks_rq(server, iface), ME).is_err(), "{} {}", server, iface);
        }
        let many = vec!["203.0.113.5"; 17].join(",");
        assert!(dispatch(&ctx, &mut st, &ks_rq(&many, TUN_IFACE), ME).is_err());
        assert!(!os.ks.get());
        dispatch(&ctx, &mut st, &ks_rq("203.0.113.5,2001:db8::1", TUN_IFACE), ME).unwrap();
        assert!(os.ks.get());
    }

    #[test]
    fn kill_switch_failure_is_reported_not_hidden() {
        let (p, os) = running("ksfail");
        os.ks_fails.set(true);
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).unwrap();
        let e = dispatch(&ctx, &mut st, &ks_rq("203.0.113.5", TUN_IFACE), ME).unwrap_err();
        assert!(e.contains("0x80320009"));
        assert!(!os.ks.get());
    }

    #[test]
    fn teardown_lifts_kill_switch_and_other_user_cannot() {
        let (p, os) = running("ksoff");
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).unwrap();
        dispatch(&ctx, &mut st, &ks_rq("203.0.113.5", TUN_IFACE), ME).unwrap();
        assert!(dispatch(&ctx, &mut st, &rq("ks-off", b""), OTHER).is_err());
        assert!(os.ks.get());
        dispatch(&ctx, &mut st, &rq("teardown", b""), ME).unwrap();
        assert!(!os.ks.get());
        assert!(!os.running.get());
        // после падения ядра (оно не работает) снять защиту может кто угодно из вошедших
        os.ks.set(true);
        dispatch(&ctx, &mut st, &rq("ks-off", b""), OTHER).unwrap();
        assert!(!os.ks.get());
    }

    #[test]
    fn stop_services_keeps_kill_switch_like_linux() {
        let (p, os) = running("ksstop");
        let ctx = Ctx { paths: &p, os: &os, settle_ms: 0 };
        let mut st = State::default();
        dispatch(&ctx, &mut st, &rq("core-config", CONFIG.as_bytes()), ME).unwrap();
        dispatch(&ctx, &mut st, &rq("core-restart", b""), ME).unwrap();
        dispatch(&ctx, &mut st, &ks_rq("203.0.113.5", TUN_IFACE), ME).unwrap();
        dispatch(&ctx, &mut st, &rq("stop-services", b""), ME).unwrap();
        assert!(os.ks.get());
    }

    #[test]
    fn kill_switch_plan_blocks_everything_else_on_every_layer() {
        let plan = kill_switch_plan();
        assert!(plan.len() <= KS_MAX_FILTERS);
        for layer in KS_LAYERS {
            let on: Vec<&KsFilter> = plan.iter().filter(|f| f.layer == layer).collect();
            let blocks: Vec<&&KsFilter> = on.iter().filter(|f| !f.permit).collect();
            assert_eq!(blocks.len(), 1, "{:?}", layer);
            assert!(blocks[0].conds.is_empty(), "блок должен ловить всё");
            for f in on.iter().filter(|f| f.permit) {
                assert!(!f.conds.is_empty(), "разрешение без условий открыло бы всё");
                assert!(f.weight > blocks[0].weight);
            }
            for need in [KsCond::Loopback, KsCond::CoreApp, KsCond::TunInterface] {
                assert!(on.iter().any(|f| f.permit && f.conds == vec![need]), "{:?} {:?}", layer, need);
            }
        }
        // кроме ядра, туннеля и loopback пропускаются только DHCP и ICMPv6-служебные сообщения
        for f in plan.iter().filter(|f| f.permit) {
            match f.conds.as_slice() {
                [KsCond::Loopback] | [KsCond::CoreApp] | [KsCond::TunInterface] => {}
                [KsCond::Protocol(17), KsCond::LocalPort(68), KsCond::RemotePort(67)]
                | [KsCond::Protocol(17), KsCond::LocalPort(546), KsCond::RemotePort(547)] => {}
                [KsCond::Protocol(58), KsCond::LocalPort(t)] => assert!((133..=137).contains(t)),
                other => panic!("лишнее разрешение: {:?}", other),
            }
        }
    }
}
