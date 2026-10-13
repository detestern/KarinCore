//! Операции helper'а. Каждая принимает уже разобранный запрос, **сама** проверяет
//! параметры и выполняет фиксированный набор действий. Произвольных команд и
//! путей из запроса тут нет: интерфейсы — из списка, адреса — через `IpAddr`,
//! конфигурации — через валидаторы (`xray`, `ovpn`, `wg`).

use crate::proto::Request;
use crate::sys::{self, Paths, Runner};
use crate::{ovpn, wg, xray};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

pub const UNIT: &str = "karin-proxy-daemon.service";
const FWMARK_TABLE: &str = "111";
const VPN_RESOLV: &str = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
/// Интерфейсы, с которыми вообще разрешено работать.
pub const IFACES: &[&str] = &["tun0", "tun-ovpn", "wg0"];
const FWMARK_IFACES: &[&str] = &["tun-ovpn", "wg0"];

pub struct Ctx {
    pub paths: Paths,
    pub run: Box<dyn Runner>,
    /// Пауза между SIGTERM и проверкой (в тестах 0).
    pub settle_ms: u64,
}

type Res = Result<String, String>;

pub fn dispatch(ctx: &Ctx, req: &Request) -> Res {
    match req.op.as_str() {
        "version" => Ok(format!("karincore-helper {} proto 1", env!("CARGO_PKG_VERSION"))),
        "core-config" => core_config(ctx, req),
        "core-restart" => core_restart(ctx),
        "core-stop" => {
            core_stop(ctx);
            Ok(String::new())
        }
        "ovpn-start" => ovpn_start(ctx, req),
        "ovpn-stop" => {
            ovpn_stop(ctx);
            Ok(String::new())
        }
        "wg-up" => wg_up(ctx, req),
        "wg-down" => {
            wg_down(ctx);
            Ok(String::new())
        }
        "wg-status-log" => wg_status_log(ctx),
        "route-fwmark" => route_fwmark(ctx, req),
        "route-cleanup" => {
            route_cleanup(ctx);
            Ok(String::new())
        }
        "bypass" => bypass(ctx, req),
        "ks-on" => ks_on(ctx, req),
        "ks-off" => {
            ks_off(ctx);
            Ok(String::new())
        }
        "dns-vpn" => dns_vpn(ctx),
        "dns-restore" => {
            dns_restore(ctx);
            Ok(String::new())
        }
        "geo-install" => geo_install(ctx, req),
        "logs-clear" => logs_clear(ctx),
        "teardown" => {
            ks_off(ctx);
            core_stop(ctx);
            ovpn_stop(ctx);
            wg_down(ctx);
            route_cleanup(ctx);
            dns_restore(ctx);
            Ok(String::new())
        }
        "stop-services" => {
            core_stop(ctx);
            ovpn_stop(ctx);
            dns_restore(ctx);
            Ok(String::new())
        }
        other => Err(format!("неизвестная операция: {}", other)),
    }
}

// ---------------------------------------------------------------- валидаторы

fn iface_param<'a>(req: &'a Request, allowed: &[&str]) -> Result<&'a str, String> {
    let v = req.param("iface").ok_or("не указан параметр iface")?;
    if allowed.contains(&v) {
        Ok(v)
    } else {
        Err(format!("недопустимый интерфейс: {}", v))
    }
}

fn ip_param(v: &str) -> Result<IpAddr, String> {
    v.parse::<IpAddr>().map_err(|_| format!("некорректный IP-адрес: {}", v))
}

fn utf8_body(req: &Request, what: &str) -> Result<String, String> {
    String::from_utf8(req.body.clone()).map_err(|_| format!("{}: тело запроса не является UTF-8", what))
}

// ---------------------------------------------------------------- каталоги и логи

fn ensure_log_files(ctx: &Ctx) -> Result<(), String> {
    sys::ensure_dir(&ctx.paths.log_dir, 0o755, ctx.paths.owner_uid)?;
    for f in [ctx.paths.err_log(), ctx.paths.acc_log()] {
        if let Ok(md) = fs::metadata(&f) {
            if md.len() > LOG_ROTATE_BYTES {
                let _ = fs::write(&f, "");
            }
        }
        // создаём, если нет (дописывание пустой строки не нужно — просто open)
        let _ = fs::OpenOptions::new().create(true).append(true).open(&f);
    }
    Ok(())
}

fn log_line(ctx: &Ctx, text: &str) {
    if sys::ensure_dir(&ctx.paths.log_dir, 0o755, ctx.paths.owner_uid).is_ok() {
        sys::append_log(&ctx.paths.err_log(), text);
    }
}

fn logs_clear(ctx: &Ctx) -> Res {
    sys::ensure_dir(&ctx.paths.log_dir, 0o755, ctx.paths.owner_uid)?;
    for f in [ctx.paths.err_log(), ctx.paths.acc_log()] {
        fs::write(&f, "").map_err(|e| format!("{}: {}", f.display(), e))?;
    }
    Ok(String::new())
}

// ---------------------------------------------------------------- Xray-ядро

fn core_config(ctx: &Ctx, req: &Request) -> Res {
    let body = utf8_body(req, "конфигурация Xray")?;
    ensure_log_files(ctx)?;
    let err = ctx.paths.err_log();
    let acc = ctx.paths.acc_log();
    let logs = xray::LogPaths {
        access: acc.to_str().ok_or("путь лога не UTF-8")?,
        error: err.to_str().ok_or("путь лога не UTF-8")?,
    };
    let canonical = xray::validate(&body, &logs)?;
    // 0600: в конфиге лежат ключи и токен локального прокси
    sys::write_atomic(&ctx.paths.conf_dir, "config.json", canonical.as_bytes(), 0o600, ctx.paths.owner_uid)?;
    Ok(String::new())
}

fn core_restart(ctx: &Ctx) -> Res {
    let r = ctx.run.run("systemctl", &["restart", UNIT]);
    if r.ok {
        return Ok(String::new());
    }
    let j = ctx.run.run("journalctl", &["-u", UNIT, "-n", "15", "--no-pager"]);
    let text = if j.ok { j.stdout } else { "не удалось прочитать журнал".to_string() };
    Err(text)
}

fn core_stop(ctx: &Ctx) {
    let _ = ctx.run.run("systemctl", &["stop", UNIT]);
}

// ---------------------------------------------------------------- OpenVPN

fn ovpn_start(ctx: &Ctx, req: &Request) -> Res {
    let raw = utf8_body(req, "конфигурация OpenVPN")?;
    let f = ovpn::build(&raw)?;
    sys::ensure_dir(&ctx.paths.conf_dir, 0o755, ctx.paths.owner_uid)?;
    ensure_log_files(ctx)?;
    sys::write_atomic(&ctx.paths.conf_dir, "openvpn.ovpn", f.text.as_bytes(), 0o600, ctx.paths.owner_uid)?;
    if !f.dropped.is_empty() {
        log_line(ctx, &format!("[OpenVPN] Отброшены неподдерживаемые директивы: {}", f.dropped.join(", ")));
    }
    ovpn_stop(ctx);
    let conf = ctx.paths.ovpn_conf();
    let conf_s = conf.to_str().ok_or("путь не UTF-8")?;
    let pid = ctx
        .run
        .spawn_detached("openvpn", &["--config", conf_s], &ctx.paths.err_log())?;
    Ok(format!("pid={}", pid))
}

/// Процессы openvpn, запущенные с нашим конфигом (поиск по /proc, как раньше `pkill -f`,
/// но с точным сравнением аргументов).
fn find_ovpn_pids(ctx: &Ctx) -> Vec<u32> {
    let conf = ctx.paths.ovpn_conf();
    let conf_s = match conf.to_str() {
        Some(s) => s.to_string(),
        None => return vec![],
    };
    let mut pids = Vec::new();
    if let Ok(rd) = fs::read_dir(&ctx.paths.proc_dir) {
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            let pid: u32 = match name.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let raw = match fs::read(e.path().join("cmdline")) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let args: Vec<&[u8]> = raw.split(|b| *b == 0).filter(|a| !a.is_empty()).collect();
            let is_openvpn = args
                .first()
                .map(|a| Path::new(std::str::from_utf8(a).unwrap_or("")).file_name().map(|f| f == "openvpn").unwrap_or(false))
                .unwrap_or(false);
            let has_conf = args.windows(2).any(|w| w[0] == b"--config" && w[1] == conf_s.as_bytes());
            if is_openvpn && has_conf {
                pids.push(pid);
            }
        }
    }
    pids
}

fn ovpn_stop(ctx: &Ctx) {
    let pids = find_ovpn_pids(ctx);
    for p in &pids {
        ctx.run.signal(*p, 15);
    }
    if pids.is_empty() {
        return;
    }
    for _ in 0..30 {
        if ctx.settle_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(ctx.settle_ms));
        }
        if find_ovpn_pids(ctx).is_empty() {
            return;
        }
        if ctx.settle_ms == 0 {
            break;
        }
    }
    for p in find_ovpn_pids(ctx) {
        ctx.run.signal(p, 9);
    }
}

// ---------------------------------------------------------------- WireGuard

fn wg_up(ctx: &Ctx, req: &Request) -> Res {
    let raw = utf8_body(req, "конфигурация WireGuard")?;
    let f = wg::filter(&raw)?;
    sys::ensure_dir(&ctx.paths.conf_dir, 0o755, ctx.paths.owner_uid)?;
    ensure_log_files(ctx)?;
    sys::write_atomic(&ctx.paths.conf_dir, "wg0.conf", f.text.as_bytes(), 0o600, ctx.paths.owner_uid)?;
    if !f.dropped.is_empty() {
        log_line(ctx, &format!("[WireGuard] Отброшены неподдерживаемые параметры: {}", f.dropped.join(", ")));
    }
    let conf = ctx.paths.wg_conf();
    let conf_s = conf.to_str().ok_or("путь не UTF-8")?.to_string();
    let _ = ctx.run.run("wg-quick", &["down", &conf_s]);
    let r = ctx.run.run("wg-quick", &["up", &conf_s]);
    log_line(ctx, "[WireGuard] Инициализация интерфейса wg0...");
    if !r.stdout.is_empty() {
        log_line(ctx, &r.stdout);
    }
    if !r.stderr.is_empty() {
        log_line(ctx, &r.stderr);
    }
    if r.ok {
        Ok(String::new())
    } else {
        Err(format!("Ошибка WireGuard:\n{}", r.stderr))
    }
}

fn wg_down(ctx: &Ctx) {
    let conf = ctx.paths.wg_conf();
    if conf.exists() {
        if let Some(s) = conf.to_str() {
            let _ = ctx.run.run("wg-quick", &["down", s]);
        }
    }
}

fn wg_status_log(ctx: &Ctx) -> Res {
    let r = ctx.run.run("wg", &["show", "wg0"]);
    if !r.ok {
        return Err("wg0 недоступен".into());
    }
    let parts: Vec<String> = r
        .stdout
        .lines()
        .filter(|l| l.contains("latest handshake:") || l.contains("transfer:") || l.contains("endpoint:"))
        .map(|l| l.trim().to_string())
        .collect();
    if !parts.is_empty() {
        log_line(ctx, &format!("[WireGuard Status] {}", parts.join(" | ")));
    }
    Ok(String::new())
}

// ---------------------------------------------------------------- маршрутизация

fn route_fwmark(ctx: &Ctx, req: &Request) -> Res {
    let iface = iface_param(req, FWMARK_IFACES)?;
    let r = &ctx.run;
    let _ = r.run("ip", &["rule", "del", "fwmark", "111", "lookup", FWMARK_TABLE]);
    let _ = r.run("ip", &["route", "add", "default", "dev", iface, "table", FWMARK_TABLE]);
    let _ = r.run("ip", &["rule", "add", "fwmark", "111", "lookup", FWMARK_TABLE]);
    let _ = r.run("sysctl", &["-w", &format!("net.ipv4.conf.{}.rp_filter=0", iface)]);
    let _ = r.run("sysctl", &["-w", "net.ipv4.conf.all.rp_filter=0"]);
    let _ = r.run("iptables", &["-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"]);
    let _ = r.run("iptables", &["-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"]);
    Ok(String::new())
}

fn route_cleanup(ctx: &Ctx) {
    let r = &ctx.run;
    let _ = r.run("iptables", &["-t", "nat", "-D", "POSTROUTING", "-o", "wg0", "-j", "MASQUERADE"]);
    let _ = r.run("ip", &["rule", "del", "fwmark", "111", "lookup", FWMARK_TABLE]);
    let _ = r.run("iptables", &["-t", "nat", "-D", "POSTROUTING", "-o", "tun-ovpn", "-j", "MASQUERADE"]);
}

/// Убирает исключения маршрутизации для адреса сервера, чтобы трафик до него
/// тоже шёл через туннель (режим «проксировать сам сервер»).
fn bypass(ctx: &Ctx, req: &Request) -> Res {
    let ips = req.param("ips").ok_or("не указан параметр ips")?;
    let routes = req.param("routes") == Some("1");
    let mut done = 0;
    for raw in ips.split(',').filter(|s| !s.is_empty()) {
        let ip = ip_param(raw)?;
        let v4 = match ip {
            IpAddr::V4(v) => v,
            IpAddr::V6(_) => continue, // IPv6 — в следующем релизе
        };
        let a = v4.to_string();
        let a32 = format!("{}/32", a);
        let r = &ctx.run;
        let _ = r.run("ip", &["rule", "del", "to", &a, "lookup", "main"]);
        let _ = r.run("ip", &["rule", "del", "to", &a32, "lookup", "main"]);
        if routes {
            let _ = r.run("ip", &["route", "del", &a]);
            let _ = r.run("ip", &["route", "del", &a32]);
        }
        done += 1;
    }
    Ok(format!("{}", done))
}

// ---------------------------------------------------------------- kill switch

fn ks_on(ctx: &Ctx, req: &Request) -> Res {
    let iface = iface_param(req, IFACES)?;
    let server = ip_param(req.param("server_ip").ok_or("не указан параметр server_ip")?)?;
    let server_v4 = match server {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(_) => return Err("IPv6-адрес сервера пока не поддерживается killswitch'ем".into()),
    };
    sys::ensure_dir(&ctx.paths.run_dir, 0o755, ctx.paths.owner_uid)?;
    sys::write_atomic(&ctx.paths.run_dir, "killswitch_ip", server_v4.as_bytes(), 0o644, ctx.paths.owner_uid)?;
    let r = &ctx.run;
    let _ = r.run("iptables", &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]);
    let _ = r.run("iptables", &["-A", "OUTPUT", "-o", iface, "-j", "ACCEPT"]);
    let _ = r.run("iptables", &["-A", "OUTPUT", "-d", &server_v4, "-j", "ACCEPT"]);
    // Трафик, который сам Xray отправляет в outbound "direct" (метка 255), — зона Direct
    // из пользовательских правил, её killswitch не режет.
    let _ = r.run("iptables", &["-A", "OUTPUT", "-d", "0.0.0.0/0", "-m", "mark", "--mark", "0xff", "-j", "ACCEPT"]);
    let _ = r.run("iptables", &["-A", "OUTPUT", "-j", "DROP"]);
    Ok(String::new())
}

fn ks_off(ctx: &Ctx) {
    let r = &ctx.run;
    // `-D` удаляет одно совпадение за раз; правила могли накопиться после аварийного завершения.
    for _ in 0..3 {
        let _ = r.run("iptables", &["-D", "OUTPUT", "-j", "DROP"]);
        let _ = r.run("iptables", &["-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]);
        for iface in IFACES {
            let _ = r.run("iptables", &["-D", "OUTPUT", "-o", iface, "-j", "ACCEPT"]);
        }
        let _ = r.run("iptables", &["-D", "OUTPUT", "-d", "0.0.0.0/0", "-m", "mark", "--mark", "0xff", "-j", "ACCEPT"]);
    }
    let state = ctx.paths.ks_state();
    if let Ok(saved) = fs::read_to_string(&state) {
        if let Ok(IpAddr::V4(ip)) = saved.trim().parse::<IpAddr>() {
            let ip = ip.to_string();
            for _ in 0..3 {
                let _ = r.run("iptables", &["-D", "OUTPUT", "-d", &ip, "-j", "ACCEPT"]);
            }
        }
    }
    let _ = fs::remove_file(&state);
}

// ---------------------------------------------------------------- DNS

fn dns_vpn(ctx: &Ctx) -> Res {
    sys::ensure_dir(&ctx.paths.conf_dir, 0o755, ctx.paths.owner_uid)?;
    let bak = ctx.paths.resolv_bak();
    if !bak.exists() {
        if let Ok(cur) = fs::read(&ctx.paths.resolv) {
            sys::write_atomic(&ctx.paths.conf_dir, "resolv.conf.bak", &cur, 0o644, ctx.paths.owner_uid)?;
        }
    }
    // Запись «сквозь» symlink — как раньше `cp` (resolv.conf часто ссылка на stub systemd-resolved).
    fs::write(&ctx.paths.resolv, VPN_RESOLV).map_err(|e| format!("{}: {}", ctx.paths.resolv.display(), e))?;
    Ok(String::new())
}

fn dns_restore(ctx: &Ctx) {
    let bak = ctx.paths.resolv_bak();
    if let Ok(saved) = fs::read(&bak) {
        let _ = fs::write(&ctx.paths.resolv, saved);
        let _ = fs::remove_file(&bak);
    }
}

// ---------------------------------------------------------------- geo-базы

fn geo_install(ctx: &Ctx, req: &Request) -> Res {
    let name = match req.param("name") {
        Some("geosite") => "geosite.dat",
        Some("geoip") => "geoip.dat",
        _ => return Err("name должен быть geosite или geoip".into()),
    };
    if req.body.is_empty() {
        return Err("пустой файл geo-базы".into());
    }
    sys::ensure_dir(&ctx.paths.conf_dir, 0o755, ctx.paths.owner_uid)?;
    sys::ensure_dir(&ctx.paths.geo_dir(), 0o755, ctx.paths.owner_uid)?;
    sys::write_atomic(&ctx.paths.geo_dir(), name, &req.body, 0o644, ctx.paths.owner_uid)?;
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Request;
    use crate::sys::testutil::*;
    use std::os::unix::fs::MetadataExt;

    fn ctx(tag: &str) -> (Ctx, std::rc::Rc<Fake>) {
        // Fake нужен и тесту (для журнала вызовов), и Ctx; делим через обёртку.
        struct Shared(std::rc::Rc<Fake>);
        impl Runner for Shared {
            fn run(&self, t: &str, a: &[&str]) -> sys::CmdResult {
                self.0.run(t, a)
            }
            fn spawn_detached(&self, t: &str, a: &[&str], l: &Path) -> Result<u32, String> {
                self.0.spawn_detached(t, a, l)
            }
            fn signal(&self, p: u32, s: i32) {
                self.0.signal(p, s)
            }
        }
        let fake = std::rc::Rc::new(Fake::new());
        let c = Ctx { paths: temp_paths(tag), run: Box::new(Shared(fake.clone())), settle_ms: 0 };
        (c, fake)
    }

    fn rq(op: &str, params: &[(&str, &str)], body: &[u8]) -> Request {
        Request {
            op: op.into(),
            params: params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: body.to_vec(),
        }
    }

    const GUI_XRAY: &str = r#"{"log":{"loglevel":"debug","access":"/home/u/a.log","error":"/home/u/e.log"},
      "routing":{"domainStrategy":"AsIs","rules":[{"type":"field","network":"tcp,udp","outboundTag":"proxy"}]},
      "inbounds":[{"port":2080,"listen":"127.0.0.1","protocol":"mixed","settings":{"accounts":[{"user":"karin","pass":"tok"}]}}],
      "outbounds":[{"tag":"proxy","protocol":"freedom","streamSettings":{"sockopt":{"mark":111,"interface":"wg0"}}}]}"#;

    #[test]
    fn core_config_writes_validated_0600_with_forced_logs() {
        let (c, _) = ctx("core");
        dispatch(&c, &rq("core-config", &[], GUI_XRAY.as_bytes())).unwrap();
        let path = c.paths.conf_dir.join("config.json");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("/home/u"));
        assert!(text.contains(c.paths.err_log().to_str().unwrap()));
        assert!(c.paths.err_log().exists() && c.paths.acc_log().exists());
    }

    #[test]
    fn core_config_rejects_hostile_and_leaves_old_config() {
        let (c, _) = ctx("core-bad");
        dispatch(&c, &rq("core-config", &[], GUI_XRAY.as_bytes())).unwrap();
        let before = fs::read(c.paths.conf_dir.join("config.json")).unwrap();
        let hostile = GUI_XRAY.replace("127.0.0.1", "/etc/evil.sock");
        assert!(dispatch(&c, &rq("core-config", &[], hostile.as_bytes())).is_err());
        assert_eq!(fs::read(c.paths.conf_dir.join("config.json")).unwrap(), before);
    }

    #[test]
    fn core_config_rotates_big_logs() {
        let (c, _) = ctx("rotate");
        sys::ensure_dir(&c.paths.log_dir, 0o755, c.paths.owner_uid).unwrap();
        fs::write(c.paths.err_log(), vec![b'x'; (LOG_ROTATE_BYTES + 10) as usize]).unwrap();
        dispatch(&c, &rq("core-config", &[], GUI_XRAY.as_bytes())).unwrap();
        assert_eq!(fs::metadata(c.paths.err_log()).unwrap().len(), 0);
    }

    #[test]
    fn core_restart_failure_returns_journal() {
        let (c, f) = ctx("restart");
        f.fail("systemctl restart");
        f.output("journalctl", "boom line");
        let e = dispatch(&c, &rq("core-restart", &[], b"")).unwrap_err();
        assert_eq!(e, "boom line");
        assert!(f.log().iter().any(|l| l.starts_with("journalctl -u karin-proxy-daemon.service -n 15")));
    }

    #[test]
    fn ks_on_command_sequence_and_state_file() {
        let (c, f) = ctx("ks");
        dispatch(&c, &rq("ks-on", &[("server_ip", "203.0.113.5"), ("iface", "tun0")], b"")).unwrap();
        assert_eq!(
            f.log(),
            vec![
                "iptables -A OUTPUT -o lo -j ACCEPT",
                "iptables -A OUTPUT -o tun0 -j ACCEPT",
                "iptables -A OUTPUT -d 203.0.113.5 -j ACCEPT",
                "iptables -A OUTPUT -d 0.0.0.0/0 -m mark --mark 0xff -j ACCEPT",
                "iptables -A OUTPUT -j DROP",
            ]
        );
        assert_eq!(fs::read_to_string(c.paths.ks_state()).unwrap(), "203.0.113.5");
    }

    #[test]
    fn ks_off_removes_rules_and_state() {
        let (c, f) = ctx("ksoff");
        dispatch(&c, &rq("ks-on", &[("server_ip", "203.0.113.5"), ("iface", "wg0")], b"")).unwrap();
        f.calls.borrow_mut().clear();
        dispatch(&c, &rq("ks-off", &[], b"")).unwrap();
        let log = f.log();
        assert_eq!(log.iter().filter(|l| *l == "iptables -D OUTPUT -j DROP").count(), 3);
        assert_eq!(log.iter().filter(|l| *l == "iptables -D OUTPUT -d 203.0.113.5 -j ACCEPT").count(), 3);
        assert!(!c.paths.ks_state().exists());
    }

    #[test]
    fn ks_off_ignores_garbage_state_file() {
        let (c, f) = ctx("ksgarbage");
        sys::ensure_dir(&c.paths.run_dir, 0o755, c.paths.owner_uid).unwrap();
        fs::write(c.paths.ks_state(), "1.2.3.4 -j ACCEPT; id").unwrap();
        dispatch(&c, &rq("ks-off", &[], b"")).unwrap();
        assert!(!f.log().iter().any(|l| l.contains("id")));
        assert!(!f.log().iter().any(|l| l.contains("1.2.3.4")));
    }

    #[test]
    fn ks_on_rejects_bad_params() {
        let (c, f) = ctx("ksbad");
        assert!(dispatch(&c, &rq("ks-on", &[("server_ip", "1.2.3.4"), ("iface", "eth0")], b"")).is_err());
        assert!(dispatch(&c, &rq("ks-on", &[("server_ip", "1.2.3.4/32"), ("iface", "tun0")], b"")).is_err());
        assert!(dispatch(&c, &rq("ks-on", &[("server_ip", "example.com"), ("iface", "tun0")], b"")).is_err());
        assert!(dispatch(&c, &rq("ks-on", &[("iface", "tun0")], b"")).is_err());
        assert!(dispatch(&c, &rq("ks-on", &[("server_ip", "2001:db8::1"), ("iface", "tun0")], b"")).is_err());
        assert!(f.log().is_empty());
    }

    #[test]
    fn route_fwmark_allows_only_vpn_ifaces() {
        let (c, f) = ctx("fw");
        assert!(dispatch(&c, &rq("route-fwmark", &[("iface", "tun0")], b"")).is_err());
        assert!(dispatch(&c, &rq("route-fwmark", &[("iface", "eth0")], b"")).is_err());
        dispatch(&c, &rq("route-fwmark", &[("iface", "wg0")], b"")).unwrap();
        let log = f.log();
        assert_eq!(log[1], "ip route add default dev wg0 table 111");
        assert!(log.contains(&"sysctl -w net.ipv4.conf.wg0.rp_filter=0".to_string()));
        assert!(log.contains(&"iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE".to_string()));
    }

    #[test]
    fn bypass_validates_ips_and_skips_v6() {
        let (c, f) = ctx("bypass");
        dispatch(&c, &rq("bypass", &[("ips", "203.0.113.5,2001:db8::1"), ("routes", "1")], b"")).unwrap();
        let log = f.log();
        assert_eq!(log.len(), 4);
        assert!(log.contains(&"ip route del 203.0.113.5/32".to_string()));
        f.calls.borrow_mut().clear();
        assert!(dispatch(&c, &rq("bypass", &[("ips", "1.2.3.4,evil")], b"")).is_err());
    }

    #[test]
    fn bypass_without_routes_only_deletes_rules() {
        let (c, f) = ctx("bypass2");
        dispatch(&c, &rq("bypass", &[("ips", "203.0.113.5")], b"")).unwrap();
        assert_eq!(f.log().len(), 2);
        assert!(f.log().iter().all(|l| l.starts_with("ip rule del to")));
    }

    #[test]
    fn dns_vpn_and_restore_roundtrip() {
        let (c, _) = ctx("dns");
        fs::write(&c.paths.resolv, "nameserver 192.168.1.1\n").unwrap();
        dispatch(&c, &rq("dns-vpn", &[], b"")).unwrap();
        assert_eq!(fs::read_to_string(&c.paths.resolv).unwrap(), VPN_RESOLV);
        assert_eq!(fs::read_to_string(c.paths.resolv_bak()).unwrap(), "nameserver 192.168.1.1\n");
        // повторное включение не затирает исходную копию
        dispatch(&c, &rq("dns-vpn", &[], b"")).unwrap();
        assert_eq!(fs::read_to_string(c.paths.resolv_bak()).unwrap(), "nameserver 192.168.1.1\n");
        dispatch(&c, &rq("dns-restore", &[], b"")).unwrap();
        assert_eq!(fs::read_to_string(&c.paths.resolv).unwrap(), "nameserver 192.168.1.1\n");
        assert!(!c.paths.resolv_bak().exists());
        // восстановление без копии ничего не ломает
        dispatch(&c, &rq("dns-restore", &[], b"")).unwrap();
    }

    #[test]
    fn dns_writes_through_symlink_like_cp() {
        let (c, _) = ctx("dnslink");
        let target = c.paths.conf_dir.join("stub-resolv.conf");
        fs::write(&target, "nameserver 127.0.0.53\n").unwrap();
        std::os::unix::fs::symlink(&target, &c.paths.resolv).unwrap();
        dispatch(&c, &rq("dns-vpn", &[], b"")).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), VPN_RESOLV);
    }

    #[test]
    fn geo_install_whitelists_names() {
        let (c, _) = ctx("geo");
        dispatch(&c, &rq("geo-install", &[("name", "geosite")], b"data")).unwrap();
        assert_eq!(fs::read(c.paths.geo_dir().join("geosite.dat")).unwrap(), b"data");
        assert_eq!(fs::metadata(c.paths.geo_dir().join("geosite.dat")).unwrap().mode() & 0o777, 0o644);
        assert!(dispatch(&c, &rq("geo-install", &[("name", "../../etc/passwd")], b"x")).is_err());
        assert!(dispatch(&c, &rq("geo-install", &[("name", "geoip")], b"")).is_err());
        assert!(dispatch(&c, &rq("geo-install", &[], b"x")).is_err());
    }

    #[test]
    fn ovpn_start_filters_writes_and_spawns() {
        let (c, f) = ctx("ovpn");
        let body = "client\nremote 203.0.113.9 1194\nup /tmp/x.sh\nplugin /tmp/p.so\n";
        let out = dispatch(&c, &rq("ovpn-start", &[], body.as_bytes())).unwrap();
        assert_eq!(out, "pid=4242");
        let conf = fs::read_to_string(c.paths.ovpn_conf()).unwrap();
        assert!(!conf.contains("/tmp/"));
        assert!(conf.contains("dev tun-ovpn"));
        assert_eq!(fs::metadata(c.paths.ovpn_conf()).unwrap().mode() & 0o777, 0o600);
        assert!(f.log().iter().any(|l| l.starts_with("SPAWN openvpn --config ") && l.ends_with("openvpn.ovpn")));
        let log = fs::read_to_string(c.paths.err_log()).unwrap();
        assert!(log.contains("up") && log.contains("plugin"));
    }

    #[test]
    fn ovpn_start_rejects_config_without_remote() {
        let (c, f) = ctx("ovpn-bad");
        assert!(dispatch(&c, &rq("ovpn-start", &[], b"client\nup /x\n")).is_err());
        assert!(!f.log().iter().any(|l| l.starts_with("SPAWN")));
        assert!(!c.paths.ovpn_conf().exists());
    }

    #[test]
    fn ovpn_stop_matches_exact_cmdline_only() {
        let (c, f) = ctx("ovpnstop");
        let conf = c.paths.ovpn_conf();
        let mk = |pid: &str, args: &[&str]| {
            let d = c.paths.proc_dir.join(pid);
            fs::create_dir_all(&d).unwrap();
            let mut raw = Vec::new();
            for a in args {
                raw.extend_from_slice(a.as_bytes());
                raw.push(0);
            }
            fs::write(d.join("cmdline"), raw).unwrap();
        };
        mk("100", &["/usr/bin/openvpn", "--config", conf.to_str().unwrap()]);
        mk("101", &["/usr/bin/openvpn", "--config", "/etc/other.ovpn"]);
        mk("102", &["/usr/bin/vim", "--config", conf.to_str().unwrap()]);
        mk("103", &["/usr/bin/openvpn", "--config", &format!("{}x", conf.to_str().unwrap())]);
        dispatch(&c, &rq("ovpn-stop", &[], b"")).unwrap();
        // процесс-пустышка не умирает, поэтому после SIGTERM следует SIGKILL — и только для pid 100
        assert_eq!(f.signals.borrow().as_slice(), &[(100u32, 15), (100u32, 9)]);
    }

    #[test]
    fn wg_up_filters_hooks_and_forces_policy() {
        let (c, f) = ctx("wg");
        let k1 = "A".repeat(43) + "=";
        let k2 = "B".repeat(43) + "=";
        let body = format!("[Interface]\nPrivateKey = {}\nAddress = 10.0.0.2/32\nPostUp = id > /tmp/x\nDNS = 1.1.1.1\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.1:51820\n", k1, k2);
        dispatch(&c, &rq("wg-up", &[], body.as_bytes())).unwrap();
        let conf = fs::read_to_string(c.paths.wg_conf()).unwrap();
        assert!(!conf.contains("PostUp") && !conf.contains("DNS") && !conf.contains("/tmp/"));
        assert!(conf.contains("Table = off") && conf.contains("FwMark = 255"));
        assert_eq!(fs::metadata(c.paths.wg_conf()).unwrap().mode() & 0o777, 0o600);
        let log = f.log();
        assert!(log[0].starts_with("wg-quick down "));
        assert!(log[1].starts_with("wg-quick up "));
    }

    #[test]
    fn wg_up_failure_is_reported() {
        let (c, f) = ctx("wgfail");
        f.fail("wg-quick up");
        let k1 = "A".repeat(43) + "=";
        let k2 = "B".repeat(43) + "=";
        let body = format!("[Interface]\nPrivateKey = {}\n[Peer]\nPublicKey = {}\n", k1, k2);
        let e = dispatch(&c, &rq("wg-up", &[], body.as_bytes())).unwrap_err();
        assert!(e.contains("Ошибка WireGuard"));
    }

    #[test]
    fn wg_status_log_filters_lines() {
        let (c, f) = ctx("wgstat");
        f.output("wg show wg0", "interface: wg0\n  public key: x\npeer: y\n  endpoint: 1.2.3.4:1\n  latest handshake: 5 seconds ago\n  transfer: 1 KiB received\n");
        dispatch(&c, &rq("wg-status-log", &[], b"")).unwrap();
        let log = fs::read_to_string(c.paths.err_log()).unwrap();
        assert!(log.contains("[WireGuard Status] endpoint: 1.2.3.4:1 | latest handshake: 5 seconds ago | transfer: 1 KiB received"));
        assert!(!log.contains("public key"));
    }

    #[test]
    fn teardown_runs_everything_best_effort() {
        let (c, f) = ctx("teardown");
        f.fail("systemctl stop");
        dispatch(&c, &rq("teardown", &[], b"")).unwrap();
        let log = f.log();
        assert!(log.iter().any(|l| l == "iptables -D OUTPUT -j DROP"));
        assert!(log.iter().any(|l| l == "systemctl stop karin-proxy-daemon.service"));
        assert!(log.iter().any(|l| l == "ip rule del fwmark 111 lookup 111"));
    }

    #[test]
    fn logs_clear_truncates() {
        let (c, _) = ctx("logclear");
        sys::ensure_dir(&c.paths.log_dir, 0o755, c.paths.owner_uid).unwrap();
        fs::write(c.paths.err_log(), "abc").unwrap();
        fs::write(c.paths.acc_log(), "def").unwrap();
        dispatch(&c, &rq("logs-clear", &[], b"")).unwrap();
        assert_eq!(fs::read_to_string(c.paths.err_log()).unwrap(), "");
        assert_eq!(fs::read_to_string(c.paths.acc_log()).unwrap(), "");
    }

    #[test]
    fn unknown_op_rejected() {
        let (c, _) = ctx("unk");
        assert!(dispatch(&c, &rq("format-disk", &[], b"")).is_err());
    }

    #[test]
    fn every_known_op_has_body_limit() {
        // Операции из dispatch и из proto::max_body должны совпадать — иначе операция недостижима.
        for op in [
            "version", "core-config", "core-restart", "core-stop", "ovpn-start", "ovpn-stop", "wg-up", "wg-down",
            "wg-status-log", "route-fwmark", "route-cleanup", "bypass", "ks-on", "ks-off", "dns-vpn", "dns-restore",
            "geo-install", "logs-clear", "teardown", "stop-services",
        ] {
            assert!(crate::proto::max_body(op).is_some(), "{}", op);
        }
    }
}
