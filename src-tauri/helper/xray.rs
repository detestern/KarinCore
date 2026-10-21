//! Проверка конфигурации Xray перед записью в /etc/karin-proxy/config.json.
//!
//! Xray запускается systemd-юнитом от root, поэтому любое поле конфига, которое
//! заставляет Xray открыть, создать или перезаписать файл, — это примитив
//! записи от root для локального пользователя. Здесь:
//!   * пути логов подменяются на фиксированные (root-owned каталог);
//!   * `listen` у входящих допускает только loopback-IP (никаких unix-сокетов);
//!   * верхний уровень, входящие, исходящие и streamSettings проверяются по
//!     списку разрешённых ключей — всё неизвестное отклоняется, а не пропускается;
//!   * поля с путями к файлам (`masterKeyLog`, `certificateFile`, …) запрещены;
//!   * результат — каноническая сериализация нашего собственного дерева.

use crate::json::{self, Value};
use std::net::IpAddr;

pub struct LogPaths<'a> {
    pub access: &'a str,
    pub error: &'a str,
}

const TOP_KEYS: &[&str] = &["log", "dns", "routing", "inbounds", "outbounds"];
const LOG_KEYS: &[&str] = &["loglevel", "access", "error", "dnsLog"];
const LOG_LEVELS: &[&str] = &["debug", "info", "warning", "error", "none"];

const DNS_KEYS: &[&str] = &[
    "hosts",
    "servers",
    "queryStrategy",
    "disableCache",
    "disableFallback",
    "disableFallbackIfMatch",
    "tag",
    "clientIp",
];
const DNS_SERVER_KEYS: &[&str] = &[
    "address",
    "port",
    "domains",
    "expectIPs",
    "unexpectedIPs",
    "skipFallback",
    "clientIp",
    "queryStrategy",
    "tag",
    "outboundTag",
    "finalQuery",
];
const DNS_SCHEMES: &[&str] = &[
    "udp",
    "tcp",
    "https",
    "http",
    "quic",
    "h2c",
    "tcp+local",
    "https+local",
    "quic+local",
    "udp+local",
    "h2c+local",
];

const ROUTING_KEYS: &[&str] = &["domainStrategy", "rules"];
const DOMAIN_STRATEGIES: &[&str] = &["AsIs", "IPIfNonMatch", "IPOnDemand"];
const RULE_KEYS: &[&str] = &[
    "type",
    "outboundTag",
    "inboundTag",
    "domain",
    "ip",
    "network",
    "port",
    "protocol",
    "source",
    "sourcePort",
    "user",
];

const INBOUND_KEYS: &[&str] = &["tag", "port", "listen", "protocol", "settings", "sniffing"];
const INBOUND_PROTOCOLS: &[&str] = &["mixed", "tun", "dokodemo-door", "socks", "http"];
const INBOUND_SETTINGS_KEYS: &[&str] = &[
    "accounts",
    "udp",
    "auth",
    "name",
    "mtu",
    "gateway",
    "dns",
    "address",
    "port",
    "network",
    "followRedirect",
    "userLevel",
    "ip",
];
const SNIFFING_KEYS: &[&str] = &[
    "enabled",
    "destOverride",
    "routeOnly",
    "metadataOnly",
    "domainsExcluded",
];

const OUTBOUND_KEYS: &[&str] = &["tag", "protocol", "settings", "streamSettings", "mux"];
const OUTBOUND_PROTOCOLS: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "freedom",
    "blackhole",
    "dns",
    "socks",
    "http",
];
const STREAM_KEYS: &[&str] = &[
    "network",
    "security",
    "sockopt",
    "tlsSettings",
    "realitySettings",
    "wsSettings",
    "grpcSettings",
    "httpSettings",
    "tcpSettings",
    "kcpSettings",
    "xhttpSettings",
    "httpupgradeSettings",
    "splithttpSettings",
];
const SOCKOPT_KEYS: &[&str] = &[
    "mark",
    "interface",
    "domainStrategy",
    "tcpFastOpen",
    "tcpKeepAliveInterval",
    "tcpKeepAliveIdle",
    "dialerProxy",
];

/// Ключи, которые заставляют Xray (работающий от root) читать/писать файлы по
/// произвольному пути. Запрещены на любой глубине.
const FORBIDDEN_KEYS: &[&str] = &[
    "masterKeyLog",
    "certificateFile",
    "keyFile",
    "certificates",
    "unixDomainSocket",
    "abstract",
];

const MAX_STRING: usize = 4096;
const ALLOWED_GEO_FILES: &[&str] = &["geosite.dat", "geoip.dat"];

pub fn validate(input: &str, logs: &LogPaths) -> Result<String, String> {
    let root = json::parse(input).map_err(|e| format!("Некорректный JSON конфигурации Xray: {}", e))?;
    let top = root
        .as_obj()
        .ok_or_else(|| "Конфигурация Xray должна быть JSON-объектом".to_string())?;
    check_keys(top, TOP_KEYS, "верхний уровень")?;

    let mut out: Vec<(String, Value)> = Vec::new();
    let mut has_inbounds = false;
    let mut has_outbounds = false;

    for (k, v) in top {
        match k.as_str() {
            "log" => out.push(("log".into(), rebuild_log(v, logs)?)),
            "dns" => {
                check_dns(v)?;
                scan_ext(v)?;
                out.push((k.clone(), v.clone()));
            }
            "routing" => {
                check_routing(v)?;
                scan_ext(v)?;
                out.push((k.clone(), v.clone()));
            }
            "inbounds" => {
                check_inbounds(v)?;
                has_inbounds = true;
                out.push((k.clone(), v.clone()));
            }
            "outbounds" => {
                check_outbounds(v)?;
                has_outbounds = true;
                out.push((k.clone(), v.clone()));
            }
            _ => unreachable!(),
        }
    }
    if !has_inbounds || !has_outbounds {
        return Err("В конфигурации Xray должны быть inbounds и outbounds".into());
    }
    if !top.iter().any(|(k, _)| k == "log") {
        out.insert(0, ("log".into(), rebuild_log(&Value::Obj(vec![]), logs)?));
    }

    let result = Value::Obj(out);
    deep_scan(&result)?;
    Ok(json::to_string(&result))
}

fn check_keys(obj: &[(String, Value)], allowed: &[&str], ctx: &str) -> Result<(), String> {
    for (k, _) in obj {
        if !allowed.contains(&k.as_str()) {
            return Err(format!("Недопустимое поле '{}' в конфигурации Xray ({})", k, ctx));
        }
    }
    Ok(())
}

fn obj_of<'a>(v: &'a Value, ctx: &str) -> Result<&'a Vec<(String, Value)>, String> {
    v.as_obj().ok_or_else(|| format!("{}: ожидался объект", ctx))
}

fn arr_of<'a>(v: &'a Value, ctx: &str) -> Result<&'a Vec<Value>, String> {
    v.as_arr().ok_or_else(|| format!("{}: ожидался массив", ctx))
}

fn rebuild_log(v: &Value, logs: &LogPaths) -> Result<Value, String> {
    let obj = obj_of(v, "log")?;
    check_keys(obj, LOG_KEYS, "log")?;
    let level = v
        .get("loglevel")
        .and_then(|l| l.as_str())
        .filter(|l| LOG_LEVELS.contains(l))
        .unwrap_or("warning");
    Ok(Value::Obj(vec![
        ("loglevel".into(), Value::Str(level.to_string())),
        ("access".into(), Value::Str(logs.access.to_string())),
        ("error".into(), Value::Str(logs.error.to_string())),
    ]))
}

fn check_dns(v: &Value) -> Result<(), String> {
    let obj = obj_of(v, "dns")?;
    check_keys(obj, DNS_KEYS, "dns")?;
    if let Some(servers) = v.get("servers") {
        for s in arr_of(servers, "dns.servers")? {
            match s {
                Value::Str(addr) => check_dns_address(addr)?,
                Value::Obj(o) => {
                    check_keys(o, DNS_SERVER_KEYS, "dns.servers[]")?;
                    if let Some(a) = s.get("address") {
                        let addr = a.as_str().ok_or("dns.servers[].address: ожидалась строка")?;
                        check_dns_address(addr)?;
                    }
                }
                _ => return Err("dns.servers[]: ожидалась строка или объект".into()),
            }
        }
    }
    if let Some(hosts) = v.get("hosts") {
        for (_, val) in obj_of(hosts, "dns.hosts")? {
            match val {
                Value::Str(_) => {}
                Value::Arr(a) if a.iter().all(|x| x.as_str().is_some()) => {}
                _ => return Err("dns.hosts: значения должны быть строкой или массивом строк".into()),
            }
        }
    }
    Ok(())
}

fn check_dns_address(addr: &str) -> Result<(), String> {
    if addr.is_empty() {
        return Err("Пустой адрес DNS-сервера".into());
    }
    if let Some((scheme, rest)) = addr.split_once("://") {
        if !DNS_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str()) {
            return Err(format!("Недопустимая схема DNS-сервера: {}", scheme));
        }
        if rest.is_empty() || rest.starts_with('/') {
            return Err("Некорректный адрес DNS-сервера".into());
        }
        return Ok(());
    }
    if addr == "localhost" || addr == "fakedns" || addr.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if addr
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
    {
        return Ok(());
    }
    Err(format!("Недопустимый адрес DNS-сервера: {}", addr))
}

fn check_routing(v: &Value) -> Result<(), String> {
    let obj = obj_of(v, "routing")?;
    check_keys(obj, ROUTING_KEYS, "routing")?;
    if let Some(ds) = v.get("domainStrategy") {
        let s = ds.as_str().ok_or("routing.domainStrategy: ожидалась строка")?;
        if !DOMAIN_STRATEGIES.contains(&s) {
            return Err(format!("Недопустимый domainStrategy: {}", s));
        }
    }
    if let Some(rules) = v.get("rules") {
        for r in arr_of(rules, "routing.rules")? {
            let ro = obj_of(r, "routing.rules[]")?;
            check_keys(ro, RULE_KEYS, "routing.rules[]")?;
            if let Some(t) = r.get("type") {
                if t.as_str() != Some("field") {
                    return Err("routing.rules[].type должен быть \"field\"".into());
                }
            }
        }
    }
    Ok(())
}

fn is_tag(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

fn is_iface(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

fn check_inbounds(v: &Value) -> Result<(), String> {
    for ib in arr_of(v, "inbounds")? {
        let o = obj_of(ib, "inbounds[]")?;
        check_keys(o, INBOUND_KEYS, "inbounds[]")?;

        let proto = ib
            .get("protocol")
            .and_then(|p| p.as_str())
            .ok_or("inbounds[].protocol обязателен")?;
        if !INBOUND_PROTOCOLS.contains(&proto) {
            return Err(format!("Недопустимый протокол входящего подключения: {}", proto));
        }
        let listen = ib
            .get("listen")
            .and_then(|l| l.as_str())
            .ok_or("inbounds[].listen обязателен и должен быть loopback-адресом")?;
        match listen.parse::<IpAddr>() {
            Ok(ip) if ip.is_loopback() => {}
            _ => {
                return Err(format!(
                    "inbounds[].listen должен быть loopback-адресом (127.0.0.0/8 или ::1), получено: {}",
                    listen
                ))
            }
        }
        match ib.get("port").and_then(|p| p.as_u64()) {
            Some(p) if (1..=65535).contains(&p) => {}
            _ => return Err("inbounds[].port должен быть числом 1–65535".into()),
        }
        if let Some(tag) = ib.get("tag") {
            let t = tag.as_str().ok_or("inbounds[].tag: ожидалась строка")?;
            if !is_tag(t) {
                return Err(format!("Недопустимый tag входящего подключения: {}", t));
            }
        }
        if let Some(settings) = ib.get("settings") {
            let so = obj_of(settings, "inbounds[].settings")?;
            check_keys(so, INBOUND_SETTINGS_KEYS, "inbounds[].settings")?;
            if let Some(name) = settings.get("name") {
                let n = name.as_str().ok_or("settings.name: ожидалась строка")?;
                if !is_iface(n) || !n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                    return Err(format!("Недопустимое имя TUN-интерфейса: {}", n));
                }
            }
            if let Some(accounts) = settings.get("accounts") {
                for a in arr_of(accounts, "settings.accounts")? {
                    let ao = obj_of(a, "settings.accounts[]")?;
                    check_keys(ao, &["user", "pass"], "settings.accounts[]")?;
                }
            }
        }
        if let Some(sn) = ib.get("sniffing") {
            check_keys(obj_of(sn, "sniffing")?, SNIFFING_KEYS, "sniffing")?;
        }
    }
    Ok(())
}

fn check_outbounds(v: &Value) -> Result<(), String> {
    for ob in arr_of(v, "outbounds")? {
        let o = obj_of(ob, "outbounds[]")?;
        check_keys(o, OUTBOUND_KEYS, "outbounds[]")?;
        let proto = ob
            .get("protocol")
            .and_then(|p| p.as_str())
            .ok_or("outbounds[].protocol обязателен")?;
        if !OUTBOUND_PROTOCOLS.contains(&proto) {
            return Err(format!("Недопустимый протокол исходящего подключения: {}", proto));
        }
        if let Some(tag) = ob.get("tag") {
            let t = tag.as_str().ok_or("outbounds[].tag: ожидалась строка")?;
            if !is_tag(t) {
                return Err(format!("Недопустимый tag исходящего подключения: {}", t));
            }
        }
        if let Some(settings) = ob.get("settings") {
            obj_of(settings, "outbounds[].settings")?;
        }
        if let Some(ss) = ob.get("streamSettings") {
            let so = obj_of(ss, "streamSettings")?;
            check_keys(so, STREAM_KEYS, "streamSettings")?;
            if let Some(sock) = ss.get("sockopt") {
                let sk = obj_of(sock, "sockopt")?;
                check_keys(sk, SOCKOPT_KEYS, "sockopt")?;
                if let Some(i) = sock.get("interface") {
                    let name = i.as_str().ok_or("sockopt.interface: ожидалась строка")?;
                    if !is_iface(name) {
                        return Err(format!("Недопустимое имя интерфейса в sockopt: {}", name));
                    }
                }
            }
        }
    }
    Ok(())
}

fn deep_scan(v: &Value) -> Result<(), String> {
    match v {
        Value::Str(s) => {
            if s.len() > MAX_STRING {
                return Err("Слишком длинная строка в конфигурации Xray".into());
            }
            if s.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
                return Err("Управляющий символ в строке конфигурации Xray".into());
            }
            Ok(())
        }
        Value::Arr(a) => a.iter().try_for_each(deep_scan),
        Value::Obj(o) => {
            for (k, val) in o {
                if FORBIDDEN_KEYS.contains(&k.as_str()) {
                    return Err(format!("Поле '{}' запрещено в конфигурации Xray", k));
                }
                deep_scan(val)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Значения вида `ext:файл:тег` заставляют Xray читать файл из каталога ресурсов.
/// Разрешаем только наши два файла — иначе возможен выход за каталог (`ext:../..`).
fn scan_ext(v: &Value) -> Result<(), String> {
    match v {
        Value::Str(s) => {
            let lower = s.to_ascii_lowercase();
            for prefix in ["ext:", "ext-ip:", "ext-domain:"] {
                if let Some(rest) = lower.strip_prefix(prefix) {
                    let file = rest.split(':').next().unwrap_or("");
                    if !ALLOWED_GEO_FILES.contains(&file) {
                        return Err(format!(
                            "Правило с внешним файлом '{}' не допускается (разрешены только geosite.dat и geoip.dat)",
                            file
                        ));
                    }
                }
            }
            Ok(())
        }
        Value::Arr(a) => a.iter().try_for_each(scan_ext),
        Value::Obj(o) => o.iter().try_for_each(|(_, x)| scan_ext(x)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGS: LogPaths<'static> = LogPaths {
        access: "/var/log/karin-proxy/access.log",
        error: "/var/log/karin-proxy/error.log",
    };

    // Конфиг режимов OpenVPN/WireGuard: свой DNS-слушатель на 127.0.0.1:53 и outbound "proxy" через интерфейс VPN.
    #[test]
    fn vpn_mode_config_with_dns_listener_is_accepted() {
        let cfg = r#"{
          "log": {"loglevel":"debug","access":"/home/u/a.log","error":"/home/u/e.log"},
          "routing": {"domainStrategy":"AsIs","rules":[
            {"type":"field","inboundTag":["ping-in"],"outboundTag":"proxy"},
            {"type":"field","inboundTag":["dns-in"],"outboundTag":"proxy"},
            {"type":"field","ip":["127.0.0.0/8"],"outboundTag":"direct"},
            {"type":"field","network":"tcp,udp","outboundTag":"proxy"}]},
          "inbounds": [
            {"port":2080,"listen":"127.0.0.1","protocol":"mixed","settings":{"accounts":[{"user":"karin","pass":"openvpn_mode"}]}},
            {"tag":"tun-in","port":2081,"listen":"127.0.0.1","protocol":"tun","settings":{"name":"tun0","mtu":1500,"gateway":["172.19.0.1/30"]},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"]}},
            {"tag":"dns-in","listen":"127.0.0.1","port":53,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","port":53,"network":"tcp,udp"}},
            {"tag":"ping-in","listen":"127.0.0.1","port":2082,"protocol":"mixed","settings":{"accounts":[{"user":"karin","pass":"openvpn_mode"}]}}],
          "outbounds": [
            {"tag":"proxy","protocol":"freedom","streamSettings":{"sockopt":{"mark":111,"interface":"tun-ovpn"}}},
            {"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"mark":255}}},
            {"tag":"block","protocol":"blackhole"}]
        }"#;
        let out = validate(cfg, &LOGS).unwrap();
        assert!(out.contains("\"dns-in\""));
        assert!(out.contains("/var/log/karin-proxy/error.log"));
    }

    // Конфиг в том виде, в каком его генерирует GUI в обычном (VLESS) режиме.
    fn gui_config() -> String {
        r#"{
          "log": {"loglevel":"debug","access":"/home/u/.local/share/karin-proxy/access.log","error":"/home/u/.local/share/karin-proxy/error.log"},
          "dns": {"hosts":{"dns.google":"8.8.8.8"},"servers":[{"address":"https://dns.google/dns-query","tag":"dns-direct","domains":["geosite:ru","domain:.pro"]},{"address":"1.1.1.1","port":53,"tag":"dns-proxy"}]},
          "routing": {"domainStrategy":"IPIfNonMatch","rules":[
            {"type":"field","inboundTag":["dns-in"],"outboundTag":"dns-out"},
            {"type":"field","inboundTag":["dns-direct"],"outboundTag":"direct"},
            {"type":"field","inboundTag":["dns-proxy"],"outboundTag":"proxy"},
            {"type":"field","ip":["127.0.0.0/8","fc00::/7"],"outboundTag":"direct"},
            {"type":"field","outboundTag":"direct","domain":["geosite:ru","keyword:foo"]},
            {"type":"field","network":"tcp,udp","outboundTag":"proxy"}]},
          "inbounds": [
            {"port":2080,"listen":"127.0.0.1","protocol":"mixed","settings":{"accounts":[{"user":"karin","pass":"tok"}]}},
            {"tag":"tun-in","port":2081,"listen":"127.0.0.1","protocol":"tun","settings":{"name":"tun0","mtu":1500,"gateway":["172.19.0.1/30"]},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"]}},
            {"tag":"dns-in","listen":"127.0.0.1","port":53,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","port":53,"network":"tcp,udp"}}],
          "outbounds": [
            {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"203.0.113.5","port":443,"users":[{"id":"uuid","encryption":"none","flow":"xtls-rprx-vision"}]}]},
             "streamSettings":{"network":"tcp","security":"reality","sockopt":{"mark":255},"realitySettings":{"publicKey":"k","shortId":"s","serverName":"example.com","fingerprint":"firefox","spiderX":""}}},
            {"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"mark":255}}},
            {"tag":"block","protocol":"blackhole"},
            {"tag":"dns-out","protocol":"dns"}]
        }"#
        .to_string()
    }

    fn with(replace_from: &str, to: &str) -> String {
        let c = gui_config();
        assert!(c.contains(replace_from), "тест не нашёл {}", replace_from);
        c.replace(replace_from, to)
    }

    #[test]
    fn accepts_gui_config_and_forces_log_paths() {
        let out = validate(&gui_config(), &LOGS).unwrap();
        assert!(out.contains("\"access\":\"/var/log/karin-proxy/access.log\""));
        assert!(out.contains("\"error\":\"/var/log/karin-proxy/error.log\""));
        assert!(!out.contains("/home/u"));
        // каноническая форма стабильна: повторная проверка даёт тот же текст
        assert_eq!(validate(&out, &LOGS).unwrap(), out);
    }

    #[test]
    fn missing_log_section_gets_fixed_one() {
        let cfg = r#"{"inbounds":[],"outbounds":[]}"#;
        let out = validate(cfg, &LOGS).unwrap();
        assert!(out.starts_with("{\"log\":{\"loglevel\":\"warning\""));
    }

    #[test]
    fn rejects_unknown_top_level_sections() {
        for extra in ["api", "stats", "policy", "metrics", "transport", "reverse", "observatory"] {
            let cfg = format!(r#"{{"inbounds":[],"outbounds":[],"{}":{{}}}}"#, extra);
            assert!(validate(&cfg, &LOGS).is_err(), "{}", extra);
        }
    }

    #[test]
    fn rejects_non_loopback_and_socket_listen() {
        for listen in ["0.0.0.0", "192.168.1.5", "/etc/evil.sock", "@abstract", "localhost", ""] {
            let cfg = with("\"listen\":\"127.0.0.1\",\"protocol\":\"mixed\"", &format!("\"listen\":\"{}\",\"protocol\":\"mixed\"", listen));
            assert!(validate(&cfg, &LOGS).is_err(), "listen={}", listen);
        }
        let ok = with("\"listen\":\"127.0.0.1\",\"protocol\":\"mixed\"", "\"listen\":\"::1\",\"protocol\":\"mixed\"");
        assert!(validate(&ok, &LOGS).is_ok());
    }

    #[test]
    fn rejects_inbound_without_listen() {
        let cfg = with("\"port\":2080,\"listen\":\"127.0.0.1\",", "\"port\":2080,");
        assert!(validate(&cfg, &LOGS).is_err());
    }

    #[test]
    fn rejects_unknown_protocols() {
        assert!(validate(&with("\"protocol\":\"dns\"", "\"protocol\":\"wireguard\""), &LOGS).is_err());
        assert!(validate(&with("\"protocol\":\"mixed\"", "\"protocol\":\"vmess\""), &LOGS).is_err());
    }

    #[test]
    fn rejects_file_path_primitives() {
        let ml = with(
            "\"realitySettings\":{",
            "\"tlsSettings\":{\"masterKeyLog\":\"/etc/sudoers.d/x\"},\"realitySettings\":{",
        );
        assert!(validate(&ml, &LOGS).is_err());
        let cf = with(
            "\"realitySettings\":{",
            "\"tlsSettings\":{\"certificates\":[{\"certificateFile\":\"/etc/shadow\"}]},\"realitySettings\":{",
        );
        assert!(validate(&cf, &LOGS).is_err());
    }

    #[test]
    fn rejects_unknown_stream_and_sockopt_keys() {
        // неизвестный ключ в streamSettings
        assert!(validate(&with("\"sockopt\":{\"mark\":255},\"realitySettings\"", "\"sockopt\":{\"mark\":255},\"foo\":1,\"realitySettings\""), &LOGS).is_err());
        // неизвестный ключ в sockopt
        assert!(validate(&with("\"sockopt\":{\"mark\":255}}},\n            {\"tag\":\"block\"", "\"sockopt\":{\"mark\":255,\"customSockopt\":[]}}},\n            {\"tag\":\"block\""), &LOGS).is_err());
    }

    #[test]
    fn sockopt_interface_must_be_plain_name() {
        let bad = with("\"sockopt\":{\"mark\":255}}},\n            {\"tag\":\"block\"", "\"sockopt\":{\"mark\":255,\"interface\":\"../x\"}}},\n            {\"tag\":\"block\"");
        assert!(validate(&bad, &LOGS).is_err());
        let good = with("\"sockopt\":{\"mark\":255}}},\n            {\"tag\":\"block\"", "\"sockopt\":{\"mark\":255,\"interface\":\"tun-ovpn\"}}},\n            {\"tag\":\"block\"");
        assert!(validate(&good, &LOGS).is_ok());
    }

    #[test]
    fn rejects_ext_files_outside_allowlist() {
        for bad in ["ext:../../etc/shadow:x", "ext:/etc/shadow:x", "ext:other.dat:tag", "EXT-IP:evil.dat:a"] {
            let cfg = with("\"keyword:foo\"", &format!("\"{}\"", bad));
            assert!(validate(&cfg, &LOGS).is_err(), "{}", bad);
        }
        let ok = with("\"keyword:foo\"", "\"ext:geosite.dat:ru\"");
        assert!(validate(&ok, &LOGS).is_ok());
    }

    #[test]
    fn rejects_duplicate_keys_and_garbage() {
        let cfg = r#"{"inbounds":[],"outbounds":[],"outbounds":[]}"#;
        assert!(validate(cfg, &LOGS).is_err());
        assert!(validate("not json", &LOGS).is_err());
        assert!(validate("[]", &LOGS).is_err());
    }

    #[test]
    fn requires_inbounds_and_outbounds() {
        assert!(validate(r#"{"outbounds":[]}"#, &LOGS).is_err());
        assert!(validate(r#"{"inbounds":[]}"#, &LOGS).is_err());
    }

    #[test]
    fn dns_address_schemes() {
        assert!(check_dns_address("https://dns.google/dns-query").is_ok());
        assert!(check_dns_address("tcp+local://1.1.1.1").is_ok());
        assert!(check_dns_address("1.1.1.1").is_ok());
        assert!(check_dns_address("localhost").is_ok());
        assert!(check_dns_address("unix:///run/x.sock").is_err());
        assert!(check_dns_address("file:///etc/passwd").is_err());
        assert!(check_dns_address("/etc/passwd").is_err());
        assert!(check_dns_address("").is_err());
    }

    #[test]
    fn control_chars_in_values_rejected() {
        let cfg = with("\"pass\":\"tok\"", "\"pass\":\"to\\u0000k\"");
        assert!(validate(&cfg, &LOGS).is_err());
    }

    #[test]
    fn tun_name_restricted() {
        assert!(validate(&with("\"name\":\"tun0\"", "\"name\":\"../tun0\""), &LOGS).is_err());
        assert!(validate(&with("\"name\":\"tun0\"", "\"name\":\"TUN0\""), &LOGS).is_err());
        assert!(validate(&with("\"name\":\"tun0\"", "\"name\":\"tun-x1\""), &LOGS).is_ok());
    }

    #[test]
    fn port_must_be_number_in_range() {
        assert!(validate(&with("\"port\":2080", "\"port\":0"), &LOGS).is_err());
        assert!(validate(&with("\"port\":2080", "\"port\":70000"), &LOGS).is_err());
        assert!(validate(&with("\"port\":2080", "\"port\":\"2080\""), &LOGS).is_err());
    }

    #[test]
    fn bad_routing_type_and_strategy() {
        assert!(validate(&with("\"IPIfNonMatch\"", "\"Evil\""), &LOGS).is_err());
        assert!(validate(&with("\"inboundTag\":[\"dns-in\"],\"outboundTag\":\"dns-out\"", "\"inboundTag\":[\"dns-in\"],\"outboundTag\":\"dns-out\",\"balancerTag\":\"b\""), &LOGS).is_err());
    }
}
