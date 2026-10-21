#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// **********************************
// IMPORTS
// **********************************
mod bridge;
mod diag;
mod finder;
mod helper_client;
mod subjson;
mod token;
mod wifi;

use tauri::{State, RunEvent, Emitter, Manager};
use url::Url;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose};
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use std::sync::Mutex;

// **********************************
// STATE & AUTHENTICATION
// **********************************
struct ProxyState {
    auth_token: Mutex<Option<String>>,
}

// **********************************
// CORE HELPER FUNCTIONS
// **********************************
// Логи пишет root-процесс (Xray, OpenVPN, helper) в каталог, принадлежащий root, —
// из GUI их можно только читать. Очистка идёт через helper.
const LOG_DIR: &str = "/var/log/karin-proxy";

fn get_log_paths() -> (String, String) {
    (format!("{}/error.log", LOG_DIR), format!("{}/access.log", LOG_DIR))
}

fn build_xray_rules(state: Value, priority: Vec<String>) -> Value {
    let mut xray_rules = Vec::new();
    
    if let Some(state_object) = state.as_object() {
        for tag in priority {
            if let Some(rules_list) = state_object.get(&tag).and_then(|v| v.as_array()) {
                let mut domains = Vec::new();
                let mut ips = Vec::new();
                
                for rule in rules_list {
                    let r_type = rule.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let r_val = rule.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    
                    match r_type {
                        "geosite" => domains.push(format!("geosite:{}", r_val)),
                        "domain" => domains.push(r_val.to_string()),
                        "keyword" => domains.push(format!("keyword:{}", r_val)),
                        "ip" => ips.push(r_val.to_string()),
                        _ => {}
                    }
                }
                
                // Fields inside a single Xray rule are AND-ed, so domains and IPs must be
                // separate rules (OR): otherwise "domain:.pro" + "geoip:ru" in one zone
                // would only match domains that ALSO resolve to a Russian IP.
                if !domains.is_empty() {
                    xray_rules.push(json!({
                        "type": "field",
                        "outboundTag": tag,
                        "domain": domains
                    }));
                }
                if !ips.is_empty() {
                    xray_rules.push(json!({
                        "type": "field",
                        "outboundTag": tag,
                        "ip": ips
                    }));
                }
            }
        }
    }
    json!(xray_rules)
}

// **********************************
// SUBSCRIPTION ROUTING/DNS IMPORT
// **********************************
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionResult {
    links: Vec<String>,
    imported_routing: Option<Value>,
    imported_dns: Option<Value>,
    imported_default_outbound: Option<String>,
    imported_profile_name: Option<String>,
}

fn classify_outbound_zone(outbounds: &[Value], tag: &str) -> Option<&'static str> {
    for ob in outbounds {
        if ob.get("tag").and_then(|v| v.as_str()) == Some(tag) {
            let protocol = ob.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
            return match protocol {
                "freedom" => Some("direct"),
                "blackhole" => Some("block"),
                "vless" | "vmess" | "trojan" | "shadowsocks" | "socks" | "http" => Some("proxy"),
                _ => None,
            };
        }
    }
    None
}

fn routing_rule_from_domain(raw: &str) -> Value {
    if let Some(rest) = raw.strip_prefix("geosite:") {
        json!({ "type": "geosite", "value": rest.to_lowercase() })
    } else if raw.starts_with("domain:") || raw.starts_with("full:") || raw.starts_with("regexp:") {
        // The value goes to Xray's domain list as-is, so the matcher prefix MUST stay:
        // stripping "domain:" would turn a suffix match into a plain substring match.
        json!({ "type": "domain", "value": raw })
    } else if let Some(rest) = raw.strip_prefix("keyword:") {
        json!({ "type": "keyword", "value": rest })
    } else {
        json!({ "type": "domain", "value": raw })
    }
}

fn convert_routing_to_zones(routing: &Value, outbounds: &[Value]) -> Option<Value> {
    let rules = routing.get("rules").and_then(|v| v.as_array())?;
    let mut zones = serde_json::Map::new();
    zones.insert("direct".to_string(), json!([]));
    zones.insert("proxy".to_string(), json!([]));
    zones.insert("block".to_string(), json!([]));
    let mut found_any = false;

    for rule in rules {
        let tag = match rule.get("outboundTag").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => continue,
        };
        let zone_key = match classify_outbound_zone(outbounds, tag) {
            Some(z) => z,
            None => continue,
        };
        let zone_arr = zones.get_mut(zone_key).unwrap().as_array_mut().unwrap();

        if let Some(domains) = rule.get("domain").and_then(|v| v.as_array()) {
            for d in domains {
                if let Some(s) = d.as_str() { zone_arr.push(routing_rule_from_domain(s)); found_any = true; }
            }
        }
        if let Some(ips) = rule.get("ip").and_then(|v| v.as_array()) {
            for ip in ips {
                if let Some(s) = ip.as_str() { zone_arr.push(json!({ "type": "ip", "value": s })); found_any = true; }
            }
        }
    }

    if found_any { Some(Value::Object(zones)) } else { None }
}

fn convert_dns_to_params(dns: &Value, outbounds: &[Value]) -> Option<Value> {
    let servers = dns.get("servers").and_then(|v| v.as_array())?;
    let mut domestic: Option<Value> = None;
    let mut remote: Option<Value> = None;

    for server in servers {
        let (address, tag) = if let Some(s) = server.as_str() {
            (s.to_string(), None)
        } else {
            let addr = server.get("address").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let tag = server.get("outboundTag").and_then(|v| v.as_str()).map(|s| s.to_string());
            (addr, tag)
        };
        if address.is_empty() { continue; }

        let entry = if address.starts_with("https://") || address.starts_with("http://") {
            json!({ "type": "doh", "url": address, "ip": "" })
        } else {
            json!({ "type": "dou", "url": "", "ip": address })
        };

        let zone_key = tag.as_deref().and_then(|t| classify_outbound_zone(outbounds, t));
        match zone_key {
            Some("direct") => { if domestic.is_none() { domestic = Some(entry); } }
            Some("proxy") => { if remote.is_none() { remote = Some(entry); } }
            _ => {
                if domestic.is_none() { domestic = Some(entry); }
                else if remote.is_none() { remote = Some(entry); }
            }
        }
    }

    if domestic.is_none() && remote.is_none() { None } else { Some(json!({ "domestic": domestic, "remote": remote })) }
}

fn str_field<'a>(data: &'a Value, key: &str) -> &'a str {
    data.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

fn happ_dns_entry(dns_type: &str, domain: &str, ip: &str) -> Option<Value> {
    if domain.is_empty() && ip.is_empty() { return None; }
    if dns_type.eq_ignore_ascii_case("doh") && (domain.starts_with("https://") || domain.starts_with("http://")) {
        Some(json!({ "type": "doh", "url": domain, "ip": ip }))
    } else {
        let plain = if !ip.is_empty() { ip } else { domain };
        Some(json!({ "type": "dou", "url": "", "ip": plain }))
    }
}

fn happ_rules_into_zone(zone: &mut Vec<Value>, sites: Option<&Value>, ips: Option<&Value>) {
    if let Some(arr) = sites.and_then(|v| v.as_array()) {
        for s in arr.iter().filter_map(|v| v.as_str()) {
            zone.push(routing_rule_from_domain(s));
        }
    }
    if let Some(arr) = ips.and_then(|v| v.as_array()) {
        for s in arr.iter().filter_map(|v| v.as_str()) {
            let value = if s.to_lowercase().starts_with("geoip:") { s.to_lowercase() } else { s.to_string() };
            zone.push(json!({ "type": "ip", "value": value }));
        }
    }
}

/// Значение заголовка `routing-enable`: `0` / `false` / `off` / `no` отключают импорт маршрутизации,
/// всё остальное (в том числе `1` и `true`) оставляет включённым.
fn routing_enable_value(raw: &str) -> bool {
    !matches!(raw.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no")
}

/// Строка `happ://routing/...` в теле подписки (в открытом виде или внутри base64-обёртки).
fn find_happ_routing_line(text: &str) -> Option<String> {
    let scan = |t: &str| -> Option<String> {
        t.lines()
            .map(str::trim)
            .find(|l| l.to_ascii_lowercase().starts_with("happ://routing/"))
            .map(|l| l.to_string())
    };
    scan(text).or_else(|| decode_base64_flexible(text).and_then(|d| scan(&d)))
}

fn convert_happ_routing(header: &str) -> (Option<Value>, Option<Value>, Option<String>, Option<String>) {
    let mut payload = header.trim();
    for prefix in ["happ://routing/onadd/", "happ://routing/add/", "happ://routing/"] {
        if let Some(rest) = payload.strip_prefix(prefix) { payload = rest; break; }
    }
    let payload = payload.replace("%3D", "=").replace("%3d", "=");
    let json_str = match decode_base64_flexible(&payload) { Some(s) => s, None => return (None, None, None, None) };
    let data: Value = match serde_json::from_str(&json_str) { Ok(v) => v, Err(_) => return (None, None, None, None) };

    let mut direct: Vec<Value> = Vec::new();
    let mut proxy: Vec<Value> = Vec::new();
    let mut block: Vec<Value> = Vec::new();
    happ_rules_into_zone(&mut direct, data.get("DirectSites"), data.get("DirectIp"));
    happ_rules_into_zone(&mut proxy, data.get("ProxySites"), data.get("ProxyIp"));
    happ_rules_into_zone(&mut block, data.get("BlockSites"), data.get("BlockIp"));

    let routing = if direct.is_empty() && proxy.is_empty() && block.is_empty() {
        None
    } else {
        Some(json!({ "direct": direct, "proxy": proxy, "block": block }))
    };

    let domestic = happ_dns_entry(str_field(&data, "DomesticDNSType"), str_field(&data, "DomesticDNSDomain"), str_field(&data, "DomesticDNSIp"));
    let remote = happ_dns_entry(str_field(&data, "RemoteDNSType"), str_field(&data, "RemoteDNSDomain"), str_field(&data, "RemoteDNSIp"));
    let dns = if domestic.is_none() && remote.is_none() { None } else { Some(json!({ "domestic": domestic, "remote": remote })) };

    // GlobalProxy=true means everything not matched by a rule goes through the proxy
    let default_outbound = match data.get("GlobalProxy") {
        Some(Value::Bool(b)) => Some(if *b { "proxy" } else { "direct" }.to_string()),
        Some(Value::String(s)) => match s.trim().to_lowercase().as_str() {
            "true" => Some("proxy".to_string()),
            "false" => Some("direct".to_string()),
            _ => None,
        },
        _ => None,
    };
    let name = str_field(&data, "Name").trim();
    let profile_name = if name.is_empty() { None } else { Some(name.to_string()) };

    (routing, dns, default_outbound, profile_name)
}

// **********************************
// DNS
// **********************************
// По документации Xray у DNS-сервера нет поля outboundTag: запросы сервера помечаются его `tag`
// как inboundTag, а дальше их направляет обычное правило маршрутизации.
const DNS_TAG_DIRECT: &str = "dns-direct";
const DNS_TAG_PROXY: &str = "dns-proxy";

fn dns_routing_rules() -> Vec<Value> {
    vec![
        json!({ "type": "field", "inboundTag": [DNS_TAG_DIRECT], "outboundTag": "direct" }),
        json!({ "type": "field", "inboundTag": [DNS_TAG_PROXY], "outboundTag": "proxy" }),
    ]
}

fn build_dns_server_entry(entry: &Value, dns_tag: &str, hosts: &mut serde_json::Map<String, Value>) -> Value {
    let server_type = entry.get("type").and_then(|v| v.as_str()).unwrap_or("dou");
    let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let ip = entry.get("ip").and_then(|v| v.as_str()).unwrap_or("");

    if server_type == "doh" && !url.is_empty() {
        if let Ok(parsed) = Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                if !ip.is_empty() {
                    hosts.insert(host.to_string(), json!(ip));
                }
            }
        }
        json!({ "address": url, "tag": dns_tag })
    } else {
        json!({ "address": ip, "port": 53, "tag": dns_tag })
    }
}

fn build_dns_config(dns_params: &Value, routing_state: &Value) -> Value {
    let mut domestic_domains = Vec::new();
    if let Some(rules_list) = routing_state.get("direct").and_then(|v| v.as_array()) {
        for rule in rules_list {
            let r_type = rule.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let r_val = rule.get("value").and_then(|v| v.as_str()).unwrap_or("");
            match r_type {
                "geosite" => domestic_domains.push(format!("geosite:{}", r_val)),
                "domain" => domestic_domains.push(r_val.to_string()),
                "keyword" => domestic_domains.push(format!("keyword:{}", r_val)),
                _ => {}
            }
        }
    }

    let mut hosts = serde_json::Map::new();
    let empty = json!({});
    let domestic_entry = dns_params.get("domestic").unwrap_or(&empty);
    let remote_entry = dns_params.get("remote").unwrap_or(&empty);

    let mut domestic_server = build_dns_server_entry(domestic_entry, DNS_TAG_DIRECT, &mut hosts);
    if !domestic_domains.is_empty() {
        if let Some(obj) = domestic_server.as_object_mut() {
            obj.insert("domains".to_string(), json!(domestic_domains));
        }
    }
    let remote_server = build_dns_server_entry(remote_entry, DNS_TAG_PROXY, &mut hosts);

    json!({
        "hosts": Value::Object(hosts),
        "servers": [domestic_server, remote_server]
    })
}

// **********************************
// MULTI-PROTOCOL LINK PARSING
// **********************************
fn decode_base64_flexible(input: &str) -> Option<String> {
    let cleaned = input.replace(['\n', '\r', ' ', '\t'], "");
    let engines = [
        general_purpose::STANDARD,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::URL_SAFE_NO_PAD
    ];
    for engine in &engines {
        if let Ok(bytes) = engine.decode(&cleaned) {
            if let Ok(utf8) = String::from_utf8(bytes) { return Some(utf8); }
        }
    }
    let mut padded = cleaned.clone();
    while padded.len() % 4 != 0 { padded.push('='); }
    for engine in &engines {
        if let Ok(bytes) = engine.decode(&padded) {
            if let Ok(utf8) = String::from_utf8(bytes) { return Some(utf8); }
        }
    }
    None
}

async fn resolve_server_ips(server: &str, port: u16) -> (String, Vec<String>) {
    let mut resolved_ips: Vec<String> = vec![];
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        resolved_ips.push(ip.to_string());
    } else if let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:{}", server, port)).await {
        while let Some(addr) = addrs.next() { resolved_ips.push(addr.ip().to_string()); }
    }
    if resolved_ips.is_empty() { resolved_ips.push(server.to_string()); }
    let out_addr = resolved_ips.first().unwrap_or(&server.to_string()).clone();
    (out_addr, resolved_ips)
}

// Транспорты, которые KarinCore умеет собирать. Остальные (ws, grpc, httpupgrade, kcp...) раньше молча
// превращались в tcp и соединение строилось не так, как в профиле; теперь это явная ошибка.
fn vless_network(transport_type: &str) -> Result<&'static str, String> {
    match transport_type {
        "" | "tcp" | "raw" => Ok("tcp"),
        "xhttp" | "splithttp" => Ok("xhttp"),
        other => Err(format!(
            "Транспорт «{}» в этой версии KarinCore не поддерживается. Профиль не изменён, соединение не установлено. Поддерживаются tcp и xhttp.",
            other
        )),
    }
}

async fn build_vless_or_trojan_outbound(link: &str, protocol: &str) -> Result<(Value, String, Vec<String>), String> {
    let parsed_url = Url::parse(link).map_err(|e| e.to_string())?;
    let server = parsed_url.host_str().unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_string();
    let port = parsed_url.port().unwrap_or(443);
    let secret = subjson::pct_decode(parsed_url.username());

    let (out_addr, resolved_ips) = resolve_server_ips(&server, port).await;

    let mut pbk = String::new(); let mut sid = String::new(); let mut sni = String::new();
    let mut fp = String::from("firefox"); let mut transport_type = String::from("tcp");
    let mut path = String::from("/"); let mut host = String::new(); let mut mode = String::from("auto");
    let mut spx = String::new(); let mut security = String::from("none"); let mut flow = String::new();

    for (k, v) in parsed_url.query_pairs() {
        match k.as_ref() {
            "pbk" => pbk = v.to_string(), "sid" => sid = v.to_string(), "sni" => sni = v.to_string(),
            "fp" => fp = v.to_string(), "type" => transport_type = v.to_string(), "path" => path = v.to_string(),
            "host" => host = v.to_string(), "mode" => mode = v.to_string(), "spx" => spx = v.to_string(),
            "security" => security = v.to_string(), "flow" => flow = v.to_string(),
            _ => {}
        }
    }
    if host.is_empty() { host = sni.clone(); }

    let final_network = vless_network(&transport_type)?;

    let mut stream_settings = serde_json::Map::new();
    stream_settings.insert("network".to_string(), json!(final_network));
    stream_settings.insert("security".to_string(), json!(security));
    stream_settings.insert("sockopt".to_string(), json!({ "mark": 255 }));

    if security == "reality" {
        stream_settings.insert("realitySettings".to_string(), json!({ "publicKey": pbk, "shortId": sid, "serverName": sni, "fingerprint": fp, "spiderX": spx }));
    } else if security == "tls" {
        stream_settings.insert("tlsSettings".to_string(), json!({ "serverName": sni, "allowInsecure": false, "fingerprint": fp }));
    }

    if final_network == "xhttp" { stream_settings.insert("xhttpSettings".to_string(), json!({ "path": path, "host": host, "mode": mode })); }

    let settings = if protocol == "trojan" {
        let mut server_obj = serde_json::Map::new();
        server_obj.insert("address".to_string(), json!(out_addr.clone()));
        server_obj.insert("port".to_string(), json!(port));
        server_obj.insert("password".to_string(), json!(secret));
        if !flow.is_empty() && (security == "reality" || security == "tls") { server_obj.insert("flow".to_string(), json!(flow)); }
        json!({ "servers": [Value::Object(server_obj)] })
    } else {
        let mut user_obj = serde_json::Map::new();
        user_obj.insert("id".to_string(), json!(secret));
        user_obj.insert("encryption".to_string(), json!("none"));
        if !flow.is_empty() && (security == "reality" || security == "tls") { user_obj.insert("flow".to_string(), json!(flow)); }
        json!({ "vnext": [{ "address": out_addr.clone(), "port": port, "users": [Value::Object(user_obj)] }] })
    };

    let outbound = json!({ "tag": "proxy", "protocol": protocol, "settings": settings, "streamSettings": Value::Object(stream_settings) });
    Ok((outbound, out_addr, resolved_ips))
}

async fn build_vmess_outbound(link: &str) -> Result<(Value, String, Vec<String>), String> {
    let b64_payload = link.trim_start_matches("vmess://");
    let decoded = decode_base64_flexible(b64_payload).ok_or_else(|| "Не удалось декодировать VMess-ссылку".to_string())?;
    let v: Value = serde_json::from_str(&decoded).map_err(|e| format!("Некорректный VMess JSON: {}", e))?;

    let get_str = |key: &str| -> String { v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string()).unwrap_or_default() };
    let get_str_or_num = |key: &str| -> String {
        if let Some(x) = v.get(key) {
            if let Some(s) = x.as_str() { return s.to_string(); }
            if let Some(n) = x.as_u64() { return n.to_string(); }
        }
        String::new()
    };

    let server = get_str("add");
    let port: u16 = get_str_or_num("port").parse().unwrap_or(443);
    let id = get_str("id");
    let aid: u32 = get_str_or_num("aid").parse().unwrap_or(0);
    let scy = { let s = get_str("scy"); if s.is_empty() { "auto".to_string() } else { s } };
    let net = { let s = get_str("net"); if s.is_empty() { "tcp".to_string() } else { s } };
    let header_type = get_str("type");
    let host = get_str("host");
    let path = { let s = get_str("path"); if s.is_empty() { "/".to_string() } else { s } };
    let tls = get_str("tls");
    let sni = { let s = get_str("sni"); if s.is_empty() { host.clone() } else { s } };
    let fp = { let s = get_str("fp"); if s.is_empty() { "firefox".to_string() } else { s } };

    if server.is_empty() || id.is_empty() {
        return Err("VMess-ссылка не содержит адрес сервера или id".into());
    }

    let (out_addr, resolved_ips) = resolve_server_ips(&server, port).await;

    let mut stream_settings = serde_json::Map::new();
    stream_settings.insert("network".to_string(), json!(net));
    stream_settings.insert("sockopt".to_string(), json!({ "mark": 255 }));

    match net.as_str() {
        "ws" => { stream_settings.insert("wsSettings".to_string(), json!({ "path": path, "headers": { "Host": host } })); }
        "grpc" => { stream_settings.insert("grpcSettings".to_string(), json!({ "serviceName": path.trim_start_matches('/') })); }
        "h2" | "http" => { stream_settings.insert("httpSettings".to_string(), json!({ "path": path, "host": [host] })); }
        _ => {
            if header_type == "http" {
                stream_settings.insert("tcpSettings".to_string(), json!({ "header": { "type": "http", "request": { "path": [path], "headers": { "Host": [host] } } } }));
            }
        }
    }

    if tls == "tls" {
        stream_settings.insert("security".to_string(), json!("tls"));
        stream_settings.insert("tlsSettings".to_string(), json!({ "serverName": sni, "allowInsecure": false, "fingerprint": fp }));
    } else {
        stream_settings.insert("security".to_string(), json!("none"));
    }

    let mut user_obj = serde_json::Map::new();
    user_obj.insert("id".to_string(), json!(id));
    user_obj.insert("alterId".to_string(), json!(aid));
    user_obj.insert("security".to_string(), json!(scy));

    let outbound = json!({
        "tag": "proxy",
        "protocol": "vmess",
        "settings": { "vnext": [{ "address": out_addr.clone(), "port": port, "users": [Value::Object(user_obj)] }] },
        "streamSettings": Value::Object(stream_settings)
    });
    Ok((outbound, out_addr, resolved_ips))
}

/// `host:port` или `[ipv6]:port` -> (хост без скобок, порт; по умолчанию 443).
fn split_host_port(hostport: &str) -> (String, u16) {
    let hostport = hostport.split(['?', '/']).next().unwrap_or(hostport);
    if let Some(rest) = hostport.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(443);
            return (host.to_string(), port);
        }
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().unwrap_or(443)),
        None => (hostport.to_string(), 443),
    }
}

fn split_shadowsocks_userinfo(decoded: &str) -> Option<(String, String)> {
    let mut parts = decoded.splitn(2, ':');
    let method = parts.next()?.to_string();
    let password = parts.next()?.to_string();
    Some((method, password))
}

async fn build_shadowsocks_outbound(link: &str) -> Result<(Value, String, Vec<String>), String> {
    let body = link.trim_start_matches("ss://");
    let body = body.split('#').next().unwrap_or(body);

    let (method, password, server, port) = if let Some(at_pos) = body.rfind('@') {
        let (userinfo_b64, hostport) = body.split_at(at_pos);
        let hostport = &hostport[1..];
        let userinfo = decode_base64_flexible(userinfo_b64).unwrap_or_else(|| userinfo_b64.to_string());
        let (method, password) = split_shadowsocks_userinfo(&userinfo).ok_or_else(|| "Некорректные учётные данные Shadowsocks".to_string())?;
        let (host, port) = split_host_port(hostport);
        (method, password, host, port)
    } else {
        let decoded = decode_base64_flexible(body).ok_or_else(|| "Не удалось декодировать Shadowsocks-ссылку".to_string())?;
        let at_pos = decoded.rfind('@').ok_or_else(|| "Некорректный формат Shadowsocks-ссылки".to_string())?;
        let (cred, hostport) = decoded.split_at(at_pos);
        let hostport = &hostport[1..];
        let (method, password) = split_shadowsocks_userinfo(cred).ok_or_else(|| "Некорректные учётные данные Shadowsocks".to_string())?;
        let (host, port) = split_host_port(hostport);
        (method, password, host, port)
    };

    if server.is_empty() || method.is_empty() {
        return Err("Shadowsocks-ссылка не содержит метод шифрования или адрес сервера".into());
    }

    let (out_addr, resolved_ips) = resolve_server_ips(&server, port).await;

    let outbound = json!({
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": { "servers": [{ "address": out_addr.clone(), "port": port, "method": method, "password": password }] },
        "streamSettings": { "sockopt": { "mark": 255 } }
    });
    Ok((outbound, out_addr, resolved_ips))
}

async fn build_proxy_outbound(link: &str) -> Result<(Value, String, Vec<String>), String> {
    if link.starts_with("vmess://") { return build_vmess_outbound(link).await; }
    if link.starts_with("trojan://") { return build_vless_or_trojan_outbound(link, "trojan").await; }
    if link.starts_with("ss://") { return build_shadowsocks_outbound(link).await; }
    build_vless_or_trojan_outbound(link, "vless").await
}

async fn ensure_geo_files() -> Result<(), String> {
    let files = vec![
        ("geosite", "geosite.dat", "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"),
        ("geoip", "geoip.dat", "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"),
    ];

    for (name, filename, url) in files {
        let final_path = format!("/etc/karin-proxy/geo/{}", filename);
        if !Path::new(&final_path).exists() {
            let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
            let content = response.bytes().await.map_err(|e| e.to_string())?;
            // Файл ставит helper: он сам создаёт каталог и пишет файл атомарно от root.
            helper_client::call("geo-install", &[("name", name)], Some(&content[..]))?;
        }
    }

    Ok(())
}

// **********************************
// XRAY
// **********************************
// TUN-inbound появился в Xray 26.1.13 (13 января 2026); в более ранних версиях ядро не поднимет tun0.
// Единственный поддерживаемый путь — /usr/bin/xray (пакет из репозитория дистрибутива).
const XRAY_MIN_VERSION: (u32, u32, u32) = (26, 1, 13);
const XRAY_PATH: &str = "/usr/bin/xray";

fn parse_xray_version(output: &str) -> Option<(u32, u32, u32)> {
    for token in output.split_whitespace() {
        let cleaned = token.trim_start_matches('v');
        let parts: Vec<&str> = cleaned.split('.').collect();
        if parts.len() == 3 {
            if let (Ok(a), Ok(b), Ok(c)) = (
                parts[0].parse::<u32>(),
                parts[1].parse::<u32>(),
                parts[2].parse::<u32>(),
            ) {
                return Some((a, b, c));
            }
        }
    }
    None
}

fn ensure_xray() -> Result<(), String> {
    if !Path::new(XRAY_PATH).exists() {
        return Err(format!(
            "Xray не найден по пути {}. Установите его пакетным менеджером: \
             sudo pacman -S xray (Arch); на Debian/Ubuntu поставьте релиз XTLS так, чтобы бинарник лежал в {}; \
             systemd-юнит karin-proxy-daemon запускает только его.",
            XRAY_PATH, XRAY_PATH
        ));
    }

    let output = std::process::Command::new(XRAY_PATH)
        .arg("version")
        .output()
        .map_err(|e| format!("Не удалось запустить {} для проверки версии: {}", XRAY_PATH, e))?;
    if !output.status.success() {
        return Err(format!("{} version завершился с ошибкой: {}", XRAY_PATH, String::from_utf8_lossy(&output.stderr).trim()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);

    match parse_xray_version(&stdout) {
        Some(v) if v >= XRAY_MIN_VERSION => Ok(()),
        Some(v) => Err(format!(
            "Установленная версия Xray {}.{}.{} слишком старая (нужна {}.{}.{} или новее, TUN-inbound). \
             Обновите пакет: sudo pacman -Syu xray (или пересоберите karincore-git).",
            v.0, v.1, v.2, XRAY_MIN_VERSION.0, XRAY_MIN_VERSION.1, XRAY_MIN_VERSION.2
        )),
        None => Err(format!(
            "Не удалось определить версию Xray из вывода `{} version`: {:?}",
            XRAY_PATH,
            stdout.lines().next().unwrap_or("")
        )),
    }
}

fn daemon_unit_installed() -> bool {
    std::process::Command::new("systemctl")
        .args(["list-unit-files", "--no-legend", "karin-proxy-daemon.service"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

// Централизованный рестарт ядра: сначала проверяем, что systemd-юнит вообще
// установлен (иначе сразу понятная ошибка вместо "ядро упало"), затем
// перезапускаем и, если не вышло, прикладываем последние строки journalctl.
fn restart_core_daemon() -> Result<(), String> {
    if !daemon_unit_installed() {
        return Err("Системный сервис karin-proxy-daemon.service не установлен. Похоже, пакет установлен некорректно — переустановите KarinCore.".into());
    }

    helper_client::call("core-restart", &[], None)
        .map(|_| ())
        .map_err(|log| format!("Ядро (karin-proxy-daemon.service) не запустилось. Лог:\n{}", log))
}

// Ждём, пока Xray реально поднимет SOCKS/HTTP inbound на 2080, вместо
// фиксированной паузы — на "холодном" старте systemd 1.5с иногда не хватает,
// из-за чего первое подключение выглядело неудачным и требовало второго клика.
async fn wait_for_core_ready() -> bool {
    for _ in 0..15 {
        if tokio::net::TcpStream::connect("127.0.0.1:2080").await.is_ok() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    false
}

const KS_FAILED_PREFIX: &str = "KS_FAILED:";

fn teardown_connections() {
    // Всё привилегированное (killswitch, ядро, OpenVPN, WireGuard, маршруты, DNS) снимает helper.
    helper_client::call_quiet("teardown", &[]);
}

// Killswitch: разрешаем OUTPUT-трафик только через loopback, туннельный
// интерфейс и напрямую до самого VPN-сервера (нужно для хендшейка) — всё
// остальное блокируется правилом DROP в конце цепочки. Правила живут вне
// цикла route.sh up/down, поэтому переживают падение/автоперезапуск демона
// (systemd Restart=on-failure) — снимаются только явным отключением или
// новой попыткой подключения через teardown_connections().
// Адреса сервера передаются списком (IPv4 и IPv6 вместе): helper раскладывает их
// по iptables / ip6tables. Больше 16 адресов helper не принимает.
// Результат важен: если Kill Switch не включился, подключаться нельзя (защита либо есть, либо нет).
// Ошибка получает префикс KS_FAILED:, по нему интерфейс показывает отдельное окно.
fn enable_kill_switch(server_ips: &[String], tun_iface: &str) -> Result<(), String> {
    let list = ip_list_param(&server_ips.iter().take(16).cloned().collect::<Vec<_>>());
    if list.is_empty() {
        return Err(format!("{}не удалось определить IP-адрес сервера, правила не на что строить", KS_FAILED_PREFIX));
    }
    helper_client::call("ks-on", &[("server_ip", list.as_str()), ("iface", tun_iface)], None)
        .map(|_| ())
        .map_err(|e| format!("{}{}", KS_FAILED_PREFIX, e))
}

// IP-адреса, пригодные для параметра helper'а (остальное — например, имя хоста, оставшееся
// после неудачного резолва — отбрасываем).
fn ip_list_param(ips: &[String]) -> String {
    ips.iter()
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
        .cloned()
        .collect::<Vec<_>>()
        .join(",")
}

// Фильтрация конфигураций OpenVPN и WireGuard (allowlist директив) выполняется в helper'е,
// на стороне root: граница привилегий проходит там, а не в GUI.

// **********************************
// TAURI COMMANDS: PROXY & NETWORK MANAGEMENT
// **********************************
// DNS в режимах OpenVPN и WireGuard. route.sh направляет системный DNS на 127.0.0.1:53, а Xray-конфиги
// этих режимов раньше такого слушателя не имели: интернет был, а имена не разрешались. Теперь Xray
// слушает 127.0.0.1:53 и пересылает запросы на 1.1.1.1 через туннель (outbound "proxy", то есть
// через интерфейс VPN), как обычный режим пересылает их через свой DNS-модуль.
const VPN_MODE_DNS_UPSTREAM: &str = "1.1.1.1";

fn vpn_mode_dns_inbound() -> Value {
    json!({ "tag": "dns-in", "listen": "127.0.0.1", "port": 53, "protocol": "dokodemo-door",
            "settings": { "address": VPN_MODE_DNS_UPSTREAM, "port": 53, "network": "tcp,udp" } })
}

fn vpn_mode_dns_rule() -> Value {
    json!({ "type": "field", "inboundTag": ["dns-in"], "outboundTag": "proxy" })
}

#[tauri::command]
async fn fetch_subscription(url: String) -> Result<SubscriptionResult, String> {
    let client = reqwest::Client::builder()
        .user_agent("v2rayNG/1.8.5")
        .build()
        .map_err(|e| format!("Ошибка HTTP клиента: {}", e))?;
        
    let mut current_url = url.clone();
    let mut text = String::new();
    let mut attempts = 0;
    let mut routing_header: Option<String> = None;
    let mut routing_enabled = true;

    while attempts < 2 {
        let response = client.get(&current_url).send().await.map_err(|e| format!("Ошибка сети: {}", e))?;
        let status = response.status();
        if let Some(v) = response.headers().get("routing").and_then(|v| v.to_str().ok()) {
            routing_header = Some(v.to_string());
        }
        if let Some(v) = response.headers().get("routing-enable").and_then(|v| v.to_str().ok()) {
            routing_enabled = routing_enable_value(v);
        }
        text = response.text().await.map_err(|e| format!("Ошибка чтения ответа: {}", e))?;

        if !status.is_success() { 
            return Err(format!("Сервер вернул ошибку {}: {}", status.as_u16(), text.chars().take(80).collect::<String>())); 
        }
        
        let clean_check = text.trim();
        if clean_check.starts_with('{') || clean_check.starts_with('[') || clean_check.contains("\"outbounds\":") {
            if attempts == 0 {
                current_url = if current_url.contains('?') { 
                    format!("{}&flag=v2ray", current_url) 
                } else { 
                    format!("{}?flag=v2ray", current_url) 
                };
                attempts += 1;
                continue;
            } else {
                break;
            }
        }
        break; 
    }

    let mut links = Vec::new();
    let mut imported_routing: Option<Value> = None;
    let mut imported_dns: Option<Value> = None;
    let mut imported_default_outbound: Option<String> = None;
    let mut imported_profile_name: Option<String> = None;

    let parse_json = |json_str: &str, out_links: &mut Vec<String>, out_routing: &mut Option<Value>, out_dns: &mut Option<Value>| {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
            let arr = if let Some(a) = json.as_array() {
                a.clone()
            } else {
                vec![json]
            };

            for item in arr {
                let remarks = item.get("remarks").and_then(|v| v.as_str()).unwrap_or("Proxy");
                let outbounds_arr = item.get("outbounds").and_then(|v| v.as_array()).cloned().unwrap_or_default();

                if let Some(link) = subjson::first_outbound_link(&outbounds_arr, remarks) {
                    out_links.push(link);
                }

                if out_routing.is_none() {
                    if let Some(routing) = item.get("routing") {
                        if let Some(converted) = convert_routing_to_zones(routing, &outbounds_arr) {
                            *out_routing = Some(converted);
                        }
                    }
                }
                if out_dns.is_none() {
                    if let Some(dns) = item.get("dns") {
                        if let Some(converted) = convert_dns_to_params(dns, &outbounds_arr) {
                            *out_dns = Some(converted);
                        }
                    }
                }
            }
        }
    };

    let parse_plain = |text_str: &str, out_links: &mut Vec<String>| {
        for line in text_str.lines() {
            let s = line.trim();
            if s.starts_with("vless://") || s.starts_with("vmess://") || s.starts_with("trojan://") || s.starts_with("ss://") {
                out_links.push(s.to_string());
            }
        }
    };

    parse_json(&text, &mut links, &mut imported_routing, &mut imported_dns);
    if links.is_empty() { parse_plain(&text, &mut links); }

    if links.is_empty() {
        let b64 = text.replace(['\n', '\r', ' ', '\t'], "");
        let engines = [
            general_purpose::STANDARD, 
            general_purpose::STANDARD_NO_PAD, 
            general_purpose::URL_SAFE, 
            general_purpose::URL_SAFE_NO_PAD
        ];
        
        let mut decoded_str = String::new();
        let mut decoded = false;

        for engine in &engines {
            if let Ok(bytes) = engine.decode(&b64) {
                if let Ok(utf8) = String::from_utf8(bytes) { 
                    decoded_str = utf8; decoded = true; break; 
                }
            }
        }
        
        if !decoded {
            let mut padded = b64.clone();
            while padded.len() % 4 != 0 { padded.push('='); }
            for engine in &engines {
                if let Ok(bytes) = engine.decode(&padded) {
                    if let Ok(utf8) = String::from_utf8(bytes) { 
                        decoded_str = utf8; decoded = true; break; 
                    }
                }
            }
        }
        
        if decoded {
            parse_json(&decoded_str, &mut links, &mut imported_routing, &mut imported_dns);
            if links.is_empty() { parse_plain(&decoded_str, &mut links); }
        }
    }

    if links.is_empty() {
        return Err("Не удалось найти профили.\nВозможно формат не поддерживается.".into());
    }

    if routing_enabled {
        // Заголовок `Routing` приоритетнее; если его нет, берём `happ://routing/...` из тела подписки.
        if routing_header.is_none() {
            routing_header = find_happ_routing_line(&text);
        }
        if let Some(header) = routing_header.as_deref() {
            let (header_routing, header_dns, header_outbound, header_name) = convert_happ_routing(header);
            imported_default_outbound = header_outbound;
            imported_profile_name = header_name;
            if imported_routing.is_none() { imported_routing = header_routing; }
            if imported_dns.is_none() { imported_dns = header_dns; }
        }
    }

    Ok(SubscriptionResult { links, imported_routing, imported_dns, imported_default_outbound, imported_profile_name })
}

async fn start_openvpn_proxy(
    _state: State<'_, ProxyState>,
    ovpn_link: String,
    routing_state: serde_json::Value,
    default_outbound: String,
    _dns_params: serde_json::Value,
    allow_server_proxy: bool,
    zone_priority: Vec<String>,
    proxy_lan: bool,
    kill_switch: bool
) -> Result<String, String> {
    let parsed_url = Url::parse(&ovpn_link).map_err(|e| e.to_string())?;
    
    let mut b64_payload = String::new();
    for (k, v) in parsed_url.query_pairs() {
        if k == "payload" { b64_payload = v.to_string(); }
    }

    if b64_payload.is_empty() { return Err("Ошибка: В полученной ссылке отсутствует payload конфигурации".into()); }

    let decoded_bytes = general_purpose::STANDARD.decode(&b64_payload).map_err(|e| format!("Ошибка декодирования Base64: {}", e))?;
    let ovpn_config = String::from_utf8(decoded_bytes).map_err(|e| format!("Ошибка UTF-8 при сборке конфигурации: {}", e))?;

    let mut resolved_ips_for_route_del: Vec<String> = vec![];
    for line in ovpn_config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("remote ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let host = parts[1];
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    resolved_ips_for_route_del.push(ip.to_string());
                } else if let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:80", host)).await {
                    while let Some(addr) = addrs.next() {
                        resolved_ips_for_route_del.push(addr.ip().to_string());
                    }
                }
            }
        }
    }

    // Фильтрацию директив (allowlist), запись конфигурации и запуск OpenVPN выполняет helper
    // от root. Служебные директивы (dev, mark, tun-mtu, script-security 0, pull-filter) он
    // добавляет сам.
    let _ = helper_client::call("dns-vpn", &[], None);
    helper_client::call_quiet("core-stop", &[]);
    helper_client::call("ovpn-start", &[], Some(ovpn_config.as_bytes()))
        .map_err(|e| format!("Не удалось запустить OpenVPN: {}", e))?;

    let mut attempts = 0;
    while attempts < 20 {
        if std::path::Path::new("/sys/class/net/tun-ovpn").exists() {
            let _ = helper_client::call("route-fwmark", &[("iface", "tun-ovpn")], None);
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        attempts += 1;
    }

    if attempts >= 20 { teardown_connections(); return Err("Таймаут: сервер OpenVPN не отвечает".into()); }

    let dynamic_rules = build_xray_rules(routing_state, zone_priority);

    let mut all_rules = vec![];
    all_rules.push(json!({ "type": "field", "inboundTag": ["ping-in"], "outboundTag": "proxy" }));
    all_rules.push(vpn_mode_dns_rule());
    let mut local_ips = vec!["127.0.0.0/8".to_string()];
    if !proxy_lan {
        local_ips.extend(vec![
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
            "192.168.0.0/16".to_string(),
            "fc00::/7".to_string(),
            "fe80::/10".to_string(),
        ]);
    }
    all_rules.push(json!({ "type": "field", "ip": local_ips, "outboundTag": "direct" }));
    if let Some(rules_array) = dynamic_rules.as_array() { all_rules.extend(rules_array.clone()); }
    all_rules.push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": default_outbound }));

    let (err_log, acc_log) = get_log_paths();

    let config = serde_json::json!({
        "log": { "loglevel": "debug", "access": acc_log, "error": err_log },
        "routing": { "domainStrategy": "AsIs", "rules": all_rules },
        "inbounds": [
            { "port": 2080, "listen": "127.0.0.1", "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": "openvpn_mode" } ] } },
            { "tag": "tun-in", "port": 2081, "listen": "127.0.0.1", "protocol": "tun", "settings": { "name": "tun0", "mtu": 1500, "gateway": ["172.19.0.1/30"] }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] } },
            vpn_mode_dns_inbound(),
            { "tag": "ping-in", "listen": "127.0.0.1", "port": 2082, "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": "openvpn_mode" } ] } }
        ],
        "outbounds": [
            { "tag": "proxy", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 111, "interface": "tun-ovpn" } } },
            { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 255 } } },
            { "tag": "block", "protocol": "blackhole" }
        ]
    });

    // helper проверяет конфигурацию (allowlist, фиксированные пути логов, listen только на loopback)
    // и сам записывает её в /etc/karin-proxy/config.json.
    helper_client::call("core-config", &[], Some(config.to_string().as_bytes()))
        .map_err(|e| format!("Не удалось применить конфигурацию Xray: {}", e))?;

    if let Err(e) = restart_core_daemon() { teardown_connections(); return Err(e); }

    if let Ok(mut guard) = _state.auth_token.lock() { *guard = Some("openvpn_mode".to_string()); }
    if !wait_for_core_ready().await {
        teardown_connections();
        return Err("Ядро не успело подняться (порт 2080 не отвечает). Попробуйте подключиться ещё раз.".into());
    }

    if kill_switch {
        if let Err(e) = enable_kill_switch(&resolved_ips_for_route_del, "tun-ovpn") {
            teardown_connections();
            return Err(e);
        }
    }

    if allow_server_proxy && !resolved_ips_for_route_del.is_empty() {
        let ips = ip_list_param(&resolved_ips_for_route_del);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            if !ips.is_empty() {
                let _ = helper_client::call("bypass", &[("ips", ips.as_str()), ("routes", "1")], None);
            }
        });
    }

    Ok("OK".into())
}

async fn start_wireguard_proxy(
    _state: State<'_, ProxyState>,
    wg_link: String,
    routing_state: serde_json::Value,
    default_outbound: String,
    _dns_params: serde_json::Value,
    allow_server_proxy: bool,
    zone_priority: Vec<String>,
    proxy_lan: bool,
    kill_switch: bool
) -> Result<String, String> {
    let parsed_url = Url::parse(&wg_link).map_err(|e| e.to_string())?;
    
    let mut b64_payload = String::new();
    for (k, v) in parsed_url.query_pairs() { if k == "payload" { b64_payload = v.to_string(); } }
    if b64_payload.is_empty() { return Err("Ошибка: В полученной ссылке отсутствует payload конфигурации".into()); }

    let decoded_bytes = general_purpose::STANDARD.decode(&b64_payload).map_err(|e| format!("Ошибка Base64: {}", e))?;
    let raw_conf = String::from_utf8(decoded_bytes).map_err(|e| format!("Ошибка UTF-8: {}", e))?;
    let original_conf = raw_conf;

    let mut resolved_ips_for_route_del: Vec<String> = vec![];
    let mut modified_conf = String::new();
    
    for line in original_conf.lines() {
        let trimmed = line.trim();
        if trimmed.to_lowercase().starts_with("dns") { continue; }
        
        if trimmed.to_lowercase().starts_with("endpoint") {
            let parts: Vec<&str> = trimmed.split('=').collect();
            if parts.len() >= 2 {
                let endpoint = parts[1].trim();
                let host = endpoint.rsplit_once(':').map(|(h, _)| h).unwrap_or(endpoint).trim_matches(|c| c == '[' || c == ']');
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    resolved_ips_for_route_del.push(ip.to_string());
                } else if let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:80", host)).await {
                    while let Some(addr) = addrs.next() { resolved_ips_for_route_del.push(addr.ip().to_string()); }
                }
            }
        }
        
        modified_conf.push_str(line); modified_conf.push('\n');
        
        if trimmed.to_lowercase() == "[interface]" {
            modified_conf.push_str("Table = off\nFwMark = 255\n"); 
        }
    }

    // Фильтрацию (allowlist ключей, без PostUp/PreUp/…), запись и `wg-quick up` выполняет helper от root.
    let _ = helper_client::call("dns-vpn", &[], None);
    helper_client::call_quiet("core-stop", &[]);
    if let Err(e) = helper_client::call("wg-up", &[], Some(modified_conf.as_bytes())) {
        teardown_connections();
        return Err(e);
    }

    let _ = helper_client::call("route-fwmark", &[("iface", "wg0")], None);

    // Раз в 3 секунды helper дописывает в лог строку со статусом рукопожатия.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3));
        loop {
            interval.tick().await;
            if !std::path::Path::new("/sys/class/net/wg0").exists() { break; }
            let _ = helper_client::call("wg-status-log", &[], None);
        }
    });

    let dynamic_rules = build_xray_rules(routing_state, zone_priority);

    let mut all_rules = vec![];
    all_rules.push(json!({ "type": "field", "inboundTag": ["ping-in"], "outboundTag": "proxy" }));
    all_rules.push(vpn_mode_dns_rule());
    let mut local_ips = vec!["127.0.0.0/8".to_string()];
    if !proxy_lan {
        local_ips.extend(vec![
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
            "192.168.0.0/16".to_string(),
            "fc00::/7".to_string(),
            "fe80::/10".to_string(),
        ]);
    }
    all_rules.push(json!({ "type": "field", "ip": local_ips, "outboundTag": "direct" }));
    if let Some(rules_array) = dynamic_rules.as_array() { all_rules.extend(rules_array.clone()); }
    all_rules.push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": default_outbound }));

    let (err_log, acc_log) = get_log_paths();

    let config = serde_json::json!({
        "log": { "loglevel": "debug", "access": acc_log, "error": err_log },
        "routing": { "domainStrategy": "AsIs", "rules": all_rules },
        "inbounds": [
            { "port": 2080, "listen": "127.0.0.1", "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": "wireguard_mode" } ] } },
            { "tag": "tun-in", "port": 2081, "listen": "127.0.0.1", "protocol": "tun", "settings": { "name": "tun0", "mtu": 1420, "gateway": ["172.19.0.1/30"] }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] } },
            vpn_mode_dns_inbound(),
            { "tag": "ping-in", "listen": "127.0.0.1", "port": 2082, "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": "wireguard_mode" } ] } }
        ],
        "outbounds": [
            { "tag": "proxy", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 111, "interface": "wg0" } } },
            { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 255 } } },
            { "tag": "block", "protocol": "blackhole" }
        ]
    });

    // helper проверяет конфигурацию (allowlist, фиксированные пути логов, listen только на loopback)
    // и сам записывает её в /etc/karin-proxy/config.json.
    helper_client::call("core-config", &[], Some(config.to_string().as_bytes()))
        .map_err(|e| format!("Не удалось применить конфигурацию Xray: {}", e))?;

    if let Err(e) = restart_core_daemon() { teardown_connections(); return Err(e); }

    if let Ok(mut guard) = _state.auth_token.lock() { *guard = Some("wireguard_mode".to_string()); }
    if !wait_for_core_ready().await {
        teardown_connections();
        return Err("Ядро не успело подняться (порт 2080 не отвечает). Попробуйте подключиться ещё раз.".into());
    }

    if kill_switch {
        if let Err(e) = enable_kill_switch(&resolved_ips_for_route_del, "wg0") {
            teardown_connections();
            return Err(e);
        }
    }

    if allow_server_proxy && !resolved_ips_for_route_del.is_empty() {
        let ips = ip_list_param(&resolved_ips_for_route_del);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            if !ips.is_empty() {
                let _ = helper_client::call("bypass", &[("ips", ips.as_str()), ("routes", "1")], None);
            }
        });
    }

    Ok("OK".into())
}

#[tauri::command]
async fn start_proxy(
    _state: State<'_, ProxyState>, 
    vless_link: String, 
    routing_state: serde_json::Value, 
    default_outbound: String,
    dns_params: serde_json::Value,
    allow_server_proxy: bool,
    zone_priority: Vec<String>,
    proxy_lan: bool,
    kill_switch: bool
) -> Result<String, String> {
    // Ядро нужно всем режимам (VLESS/OpenVPN/WireGuard): без подходящего Xray даже не начинаем.
    ensure_xray()?;

    teardown_connections();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    if vless_link.starts_with("ovpn://") {
        return start_openvpn_proxy(_state, vless_link, routing_state, default_outbound, dns_params, allow_server_proxy, zone_priority, proxy_lan, kill_switch).await;
    }

    if vless_link.starts_with("wg://") {
        return start_wireguard_proxy(_state, vless_link, routing_state, default_outbound, dns_params, allow_server_proxy, zone_priority, proxy_lan, kill_switch).await;
    }

    let token = token::generate()?;
    if let Ok(mut guard) = _state.auth_token.lock() { *guard = Some(token.clone()); }

    let (proxy_outbound, out_addr, resolved_ips) = build_proxy_outbound(&vless_link).await?;

    let dns_config = build_dns_config(&dns_params, &routing_state);
    let dynamic_rules = build_xray_rules(routing_state, zone_priority);

    let mut all_rules = vec![];
    all_rules.push(json!({ "type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out" }));
    all_rules.extend(dns_routing_rules());
    all_rules.push(json!({ "type": "field", "inboundTag": ["ping-in"], "outboundTag": "proxy" }));
    all_rules.push(vpn_mode_dns_rule());
    let mut local_ips = vec!["127.0.0.0/8".to_string()];
    if !proxy_lan {
        local_ips.extend(vec![
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
            "192.168.0.0/16".to_string(),
            "fc00::/7".to_string(),
            "fe80::/10".to_string(),
        ]);
    }
    all_rules.push(json!({ "type": "field", "ip": local_ips, "outboundTag": "direct" }));
    if let Some(rules_array) = dynamic_rules.as_array() { all_rules.extend(rules_array.clone()); }
    all_rules.push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": default_outbound }));

    let (err_log, acc_log) = get_log_paths();

    let config = serde_json::json!({
        "log": { "loglevel": "debug", "access": acc_log, "error": err_log },
        "dns": dns_config,
        "routing": { "domainStrategy": "IPIfNonMatch", "rules": all_rules },
        "inbounds": [
            { "port": 2080, "listen": "127.0.0.1", "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": token } ] } },
            { "tag": "tun-in", "port": 2081, "listen": "127.0.0.1", "protocol": "tun", "settings": { "name": "tun0", "mtu": 1500, "gateway": ["172.19.0.1/30"] }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] } },
            { "tag": "dns-in", "listen": "127.0.0.1", "port": 53, "protocol": "dokodemo-door", "settings": { "address": "1.1.1.1", "port": 53, "network": "tcp,udp" } },
            { "tag": "ping-in", "listen": "127.0.0.1", "port": 2082, "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": token } ] } }
        ],
        "outbounds": [
            proxy_outbound,
            { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 255 } } },
            { "tag": "block", "protocol": "blackhole" },
            { "tag": "dns-out", "protocol": "dns" }
        ]
    });

    // helper проверяет конфигурацию (allowlist, фиксированные пути логов, listen только на loopback)
    // и сам записывает её в /etc/karin-proxy/config.json.
    helper_client::call("core-config", &[], Some(config.to_string().as_bytes()))
        .map_err(|e| format!("Не удалось применить конфигурацию Xray: {}", e))?;

    if let Err(e) = restart_core_daemon() { teardown_connections(); return Err(e); }
    if !wait_for_core_ready().await {
        teardown_connections();
        return Err("Ядро не успело подняться (порт 2080 не отвечает). Попробуйте подключиться ещё раз.".into());
    }
    if kill_switch {
        if let Err(e) = enable_kill_switch(std::slice::from_ref(&out_addr), "tun0") {
            teardown_connections();
            return Err(e);
        }
    }
    if allow_server_proxy {
        let ips = ip_list_param(&resolved_ips);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            if !ips.is_empty() {
                let _ = helper_client::call("bypass", &[("ips", ips.as_str())], None);
            }
        });
    }
    
    Ok("OK".into())
}

#[tauri::command]
fn stop_proxy(_state: State<'_, ProxyState>) -> Result<String, String> {
    if let Ok(mut guard) = _state.auth_token.lock() { *guard = None; }
    teardown_connections();  
    Ok("Остановлено".into())
}

// **********************************
// TAURI COMMANDS: UTILITIES & NETWORK
// **********************************
#[tauri::command]
async fn get_vpn_ip(_state: State<'_, ProxyState>) -> Result<String, String> {
    let proxy_url = {
        let guard = _state.auth_token.lock().unwrap();
        if let Some(token) = guard.as_ref() { format!("http://karin:{}@127.0.0.1:2082", token) } else { "http://127.0.0.1:2082".to_string() }
    };
    let proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder().proxy(proxy).timeout(std::time::Duration::from_secs(10)).build().map_err(|e| e.to_string())?;
    let ip = client.get("http://ifconfig.me/ip").send().await.map_err(|e| format!("Ошибка сети: {}", e))?.text().await.map_err(|_e| "Ошибка парсинга".to_string())?;
    Ok(ip)
}

#[tauri::command]
async fn check_ping(_state: State<'_, ProxyState>) -> Result<String, String> {
    let proxy_url = {
        let guard = _state.auth_token.lock().unwrap();
        if let Some(token) = guard.as_ref() { format!("http://karin:{}@127.0.0.1:2082", token) } else { "http://127.0.0.1:2082".to_string() }
    };
    let proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder().proxy(proxy).timeout(std::time::Duration::from_secs(10)).build().map_err(|e| e.to_string())?;
    let start = std::time::Instant::now();
    let _ = client.get("http://cp.cloudflare.com/generate_204").send().await.map_err(|_e| "Ошибка сети".to_string())?; 
    Ok(format!("{} ms", start.elapsed().as_millis()))
}

// **********************************
// ДИАГНОСТИКА
// Пробы возвращают короткие строки; решение «что сломано» принимает diag::verdict.
// **********************************
#[tauri::command]
async fn diag_internet() -> Result<String, String> {
    // Любой из двух публичных адресов достаточно: так одиночная блокировка не даёт ложного отказа.
    for addr in ["1.1.1.1:443", "8.8.8.8:443"] {
        let attempt = tokio::time::timeout(std::time::Duration::from_secs(3), tokio::net::TcpStream::connect(addr)).await;
        if let Ok(Ok(_)) = attempt { return Ok("ok".to_string()); }
    }
    Ok("fail".to_string())
}

#[tauri::command]
async fn diag_resolve(host: String) -> Result<String, String> {
    let lookup = tokio::time::timeout(std::time::Duration::from_secs(4), tokio::net::lookup_host((host.as_str(), 443u16))).await;
    match lookup {
        Ok(Ok(mut addrs)) => {
            let found = addrs.next().is_some();
            Ok((if found { "ok" } else { "fail" }).to_string())
        }
        _ => Ok("fail".to_string()),
    }
}

#[tauri::command]
async fn diag_tcp(host: String, port: u16) -> Result<String, String> {
    let started = std::time::Instant::now();
    let attempt = tokio::time::timeout(std::time::Duration::from_secs(5), tokio::net::TcpStream::connect((host.as_str(), port))).await;
    Ok(match attempt {
        Ok(Ok(_)) => format!("open:{}", started.elapsed().as_millis()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => "refused".to_string(),
        Ok(Err(_)) => "unreachable".to_string(),
        Err(_) => "timeout".to_string(),
    })
}

/// Видимые и сохранённые Wi‑Fi сети (NetworkManager). Ошибка значит «список недоступен».
#[tauri::command]
async fn wifi_scan() -> Result<Value, String> {
    let networks = tauri::async_runtime::spawn_blocking(wifi::read_networks)
        .await
        .map_err(|e| e.to_string())??;
    Ok(Value::Array(
        networks
            .into_iter()
            .map(|n| json!({ "ssid": n.ssid, "signal": n.signal, "secure": n.secure, "inUse": n.in_use, "known": n.known }))
            .collect(),
    ))
}

/// Имя Wi‑Fi сети, к которой подключён компьютер (None — не подключён к Wi‑Fi).
#[tauri::command]
async fn wifi_current() -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(wifi::read_current_ssid)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn diag_core() -> String {
    match std::process::Command::new("pgrep").args(["-x", "xray"]).status() {
        Ok(status) if status.success() => "yes".to_string(),
        Ok(_) => "no".to_string(),
        Err(_) => "na".to_string(),
    }
}

/// Строки журнала Xray, появившиеся после позиции `from` (если файл сменился — с начала).
fn read_log_since(path: &str, from: u64) -> Vec<String> {
    let Ok(mut file) = std::fs::File::open(path) else { return Vec::new() };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = if len >= from { from } else { 0 };
    if std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(start)).is_err() { return Vec::new(); }
    let mut bytes = Vec::new();
    if std::io::Read::read_to_end(&mut file, &mut bytes).is_err() { return Vec::new(); }
    diag::tail_lines(&String::from_utf8_lossy(&bytes))
}

#[tauri::command]
async fn diag_tunnel(_state: State<'_, ProxyState>) -> Result<Value, String> {
    let proxy_url = {
        let guard = _state.auth_token.lock().unwrap();
        if let Some(token) = guard.as_ref() { format!("http://karin:{}@127.0.0.1:2082", token) } else { "http://127.0.0.1:2082".to_string() }
    };
    let proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder().proxy(proxy).timeout(std::time::Duration::from_secs(8)).build().map_err(|e| e.to_string())?;

    let (log_path, _) = get_log_paths();
    let log_start = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    let started = std::time::Instant::now();
    let response = client.get("http://cp.cloudflare.com/generate_204").send().await;
    let ms = started.elapsed().as_millis() as u64;
    let (ok, error) = match &response {
        Ok(r) if r.status().is_success() => (true, String::new()),
        Ok(r) => (false, format!("status {}", r.status().as_u16())),
        Err(e) if e.is_timeout() => (false, "timeout".to_string()),
        Err(e) if e.is_connect() => (false, "connect".to_string()),
        Err(_) => (false, "request".to_string()),
    };

    // Xray дописывает журнал с небольшой задержкой.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let log = read_log_since(&log_path, log_start);
    let state = if ok { "ok" } else { "fail" };
    Ok(json!({ "state": state, "ms": ms, "error": error, "log": log }))
}

#[tauri::command]
fn diag_verdict(
    vpn_on: bool,
    transport: String,
    internet: String,
    dns: String,
    tcp: String,
    tunnel: String,
    tunnel_ms: u64,
    tunnel_log: Vec<String>,
    core: String,
    kill_switch: bool,
) -> Value {
    let outcome = diag::verdict(&diag::Inputs {
        vpn_on,
        transport: &transport,
        internet: &internet,
        dns: &dns,
        tcp: &tcp,
        tunnel: &tunnel,
        tunnel_ms,
        tunnel_log: &tunnel_log,
        core: &core,
        kill_switch,
    });
    let steps: Vec<&str> = outcome.steps.iter().map(|s| s.as_str()).collect();
    json!({ "code": outcome.code, "detail": outcome.detail, "steps": steps })
}

#[tauri::command]
fn open_browser(url: String) { std::process::Command::new("xdg-open").arg(url).spawn().ok(); }

// Короткое системное уведомление (например, о переключении сервера при обрыве). Если notify-send
// не установлен, ничего не происходит: то же сообщение есть в самом приложении.
#[tauri::command]
fn notify_desktop(title: String, body: String) {
    let clip = |text: String| text.chars().take(200).collect::<String>();
    let _ = std::process::Command::new("notify-send")
        .args(["-a", "KarinCore", "--"])
        .arg(clip(title))
        .arg(clip(body))
        .spawn();
}

#[tauri::command]
fn get_logs() -> Result<String, String> {
    let (log_path, _) = get_log_paths();
    
    // Проверяем, существует ли файл, ДО того как его читать
    if !std::path::Path::new(&log_path).exists() {
        return Ok("Ожидание запуска прокси (файлы логов еще не созданы)...".to_string());
    }

    match std::fs::read_to_string(&log_path) {
        Ok(content) => {
            if content.trim().is_empty() { 
                return Ok("Ожидание логов (Прокси работает, ожидаем сетевой трафик)...".to_string()); 
            }
            let lines: Vec<&str> = content.lines().collect();
            let last_lines = if lines.len() > 50 { &lines[lines.len() - 50..] } else { &lines[..] };
            Ok(last_lines.join("\n"))
        },
        Err(e) => Ok(format!("Ошибка чтения логов: {}\nУбедитесь, что прокси запущен.", e))
    }
}

#[tauri::command]
fn get_geosite_list() -> Vec<String> { 
    vec!["google", "youtube", "telegram", "vk", "yandex", "mailru", "github", "netflix", "spotify", "instagram", "twitter", "facebook", "tiktok", "apple", "microsoft", "amazon", "discord", "reddit", "twitch", "ru", "cn", "us", "geolocation-!cn", "geolocation-!ru", "category-ads-all", "category-porn", "category-games", "private", "speedtest", "openai"].into_iter().map(String::from).collect() 
}

#[tauri::command]
fn clear_logs() -> Result<String, String> {
    helper_client::call("logs-clear", &[], None)?;
    Ok("Очищено".into())
}

#[tauri::command]
async fn export_profile(filename: String, content: String) -> Result<String, String> {
    let result = tokio::task::spawn_blocking(move || {
        if let Some(path) = rfd::FileDialog::new().set_title("Экспорт профиля маршрутизации").set_file_name(&filename).add_filter("JSON Config", &["json"]).save_file() {
            std::fs::write(&path, content).map_err(|e| format!("Ошибка записи: {}", e))?; Ok(format!("Сохранено в {}", path.display()))
        } else { Err("Отменено".to_string()) }
    }).await.map_err(|e| format!("Ошибка потока: {}", e))?;
    result
}

#[tauri::command]
fn minimize_window(window: tauri::Window) { let _ = window.minimize(); }

#[tauri::command]
fn maximize_window(window: tauri::Window) {
    if let Ok(maximized) = window.is_maximized() { if maximized { let _ = window.unmaximize(); } else { let _ = window.maximize(); } }
}

#[tauri::command]
fn close_window(_window: tauri::Window, _state: State<'_, ProxyState>, bridge_state: State<'_, bridge::BridgeState>) {
    if let Ok(mut guard) = _state.auth_token.lock() { *guard = None; }
    teardown_connections();
    bridge_state.exit();
    std::process::exit(0);
}

// **********************************
// МОСТИК ДЛЯ ВНЕШНИХ ОБОЛОЧЕК (karin-shell / Brain Shell)
// Статус-файл и флаги командной строки; логика в bridge.rs.
// **********************************
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BridgeProfileArg {
    url: String,
    name: String,
    #[serde(default)]
    group: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BridgeUpdateArg {
    state: String,
    #[serde(default)]
    selected_url: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    profiles: Vec<BridgeProfileArg>,
}

#[derive(Clone, Serialize)]
struct BridgeActionPayload {
    action: String,
    url: Option<String>,
}

fn emit_bridge_actions(app: &tauri::AppHandle, actions: Vec<bridge::ResolvedAction>) {
    for a in actions {
        let _ = app.emit("bridge-action", BridgeActionPayload { action: a.action.to_string(), url: a.url });
    }
}

fn focus_main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Прежнее содержимое статус-файла (список профилей), чтобы панель не видела пустоту, пока грузится интерфейс.
fn load_previous_bridge() -> Option<bridge::Previous> {
    let path = bridge::state_file_path()?;
    let text = std::fs::read_to_string(path).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let text_of = |item: &Value, key: &str| item.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let profiles = v
        .get("profiles")?
        .as_array()?
        .iter()
        .filter_map(|p| {
            let id = p.get("id")?.as_str()?.to_string();
            Some(bridge::ProfileOut { id, name: text_of(p, "name"), kind: text_of(p, "type"), group: text_of(p, "group") })
        })
        .collect();
    Some(bridge::Previous { selected: text_of(&v, "selected"), profile_name: text_of(&v, "profile_name"), profiles })
}

/// Фронтенд присылает снимок: состояние, выбранный профиль, IP и список профилей.
/// Ссылки остаются внутри приложения, в файл идут только id, имя, тип и группа.
#[tauri::command]
fn bridge_update(app: tauri::AppHandle, bridge_state: State<'_, bridge::BridgeState>, update: BridgeUpdateArg) {
    let input = bridge::UpdateIn {
        state: update.state,
        selected_url: update.selected_url,
        ip: update.ip,
        profiles: update
            .profiles
            .into_iter()
            .map(|p| bridge::ProfileIn { url: p.url, name: p.name, group: p.group })
            .collect(),
    };
    let actions = bridge_state.update(input);
    emit_bridge_actions(&app, actions);
}

// **********************************
// MAIN APPLICATION ENTRY POINT
// **********************************
fn main() {
    let argv: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    let cli = bridge::parse_cli(&argv);
    let running = bridge::running_instance_alive();

    // `--disconnect`, когда приложение не запущено: отключать нечего, ничего не делаем.
    if cli.iter().any(|a| matches!(a, bridge::CliAction::Disconnect)) && running == Some(false) {
        return;
    }

    // Если экземпляр уже работает, этот процесс лишь передаст ему флаги и выйдет (single-instance),
    // поэтому тяжёлую подготовку (xray, geo-базы) не повторяем.
    if running != Some(true) {
        if let Err(e) = ensure_xray() { eprintln!("karincore: {}", e); }
        tokio::runtime::Runtime::new().unwrap().block_on(async { let _ = ensure_geo_files().await; });
    }

    let startup_cli = cli.clone();
    let app = tauri::Builder::default()
        // Должен регистрироваться первым. Повторный запуск не открывает второе окно:
        // флаги уходят в работающий экземпляр и превращаются в те же действия, что кнопки на главном экране.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            let actions = bridge::parse_cli(&argv);
            if actions.is_empty() {
                focus_main_window(app);
            } else {
                let resolved = app.state::<bridge::BridgeState>().dispatch(actions);
                emit_bridge_actions(app, resolved);
            }
        }))
        .manage(ProxyState { auth_token: Mutex::new(None) })
        .manage(finder::FinderState::default())
        .manage(bridge::BridgeState::new(env!("CARGO_PKG_VERSION"), std::process::id(), bridge::state_file_path()))
        .setup(move |app| {
            // Первый экземпляр запущен с `--disconnect`: ничего не делаем и не пишем статус-файл.
            if startup_cli.iter().any(|a| matches!(a, bridge::CliAction::Disconnect)) {
                std::process::exit(0);
            }
            let bridge_state = app.state::<bridge::BridgeState>();
            bridge_state.start(load_previous_bridge());
            // Флаги холодного старта ждут, пока фронтенд пришлёт список профилей.
            if !startup_cli.is_empty() {
                let _ = bridge_state.dispatch(startup_cli.clone());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_proxy, stop_proxy, fetch_subscription, notify_desktop, get_geosite_list, get_logs, clear_logs, get_vpn_ip, check_ping, diag_internet, diag_resolve, diag_tcp, diag_core, diag_tunnel, wifi_scan, wifi_current, diag_verdict, export_profile, minimize_window, maximize_window, close_window, open_browser, bridge_update,
            finder::finder_start, finder::finder_mark_background, finder::finder_poll, finder::finder_result, finder::finder_stop
        ]).build(tauri::generate_context!()).expect("error while building tauri application");
    app.run(|app_handle, event| {
        if let RunEvent::ExitRequested { .. } | RunEvent::Exit = event {
            app_handle.state::<bridge::BridgeState>().exit();
            helper_client::call_quiet("stop-services", &[]);
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_enable_header_values() {
        assert!(!routing_enable_value("0"));
        assert!(!routing_enable_value(" false "));
        assert!(!routing_enable_value("OFF"));
        assert!(routing_enable_value("1"));
        assert!(routing_enable_value("true"));
        assert!(routing_enable_value(""));
    }

    #[test]
    fn happ_routing_line_found_in_body_plain_and_base64() {
        let plain = "vless://a@b:1#x\nhappe://nope\n  happ://routing/onadd/e30=  \n";
        assert_eq!(find_happ_routing_line(plain).as_deref(), Some("happ://routing/onadd/e30="));
        let wrapped = general_purpose::STANDARD.encode("trojan://p@h:443#t\nhapp://routing/add/e30=\n");
        assert_eq!(find_happ_routing_line(&wrapped).as_deref(), Some("happ://routing/add/e30="));
        assert!(find_happ_routing_line("vless://a@b:1#x").is_none());
    }

    #[test]
    fn happ_routing_payload_prefixes() {
        let payload = general_purpose::STANDARD.encode(r#"{"Name":"P","GlobalProxy":"true","DirectSites":["geosite:ru"]}"#);
        for prefix in ["happ://routing/onadd/", "happ://routing/add/", "happ://routing/"] {
            let (routing, _, outbound, name) = convert_happ_routing(&format!("{}{}", prefix, payload));
            assert!(routing.is_some(), "{}", prefix);
            assert_eq!(outbound.as_deref(), Some("proxy"));
            assert_eq!(name.as_deref(), Some("P"));
        }
    }

    #[test]
    fn host_port_split_handles_ipv6() {
        assert_eq!(split_host_port("example.com:8388"), ("example.com".to_string(), 8388));
        assert_eq!(split_host_port("[2001:db8::1]:8443"), ("2001:db8::1".to_string(), 8443));
        assert_eq!(split_host_port("[2001:db8::1]"), ("2001:db8::1".to_string(), 443));
        assert_eq!(split_host_port("example.com"), ("example.com".to_string(), 443));
    }

    #[test]
    fn dns_servers_use_tags_not_outbound_tag() {
        let params = json!({
            "domestic": { "type": "dou", "url": "", "ip": "77.88.8.8" },
            "remote": { "type": "doh", "url": "https://dns.google/dns-query", "ip": "8.8.8.8" }
        });
        let cfg = build_dns_config(&params, &json!({ "direct": [{ "type": "geosite", "value": "ru" }] }));
        let servers = cfg["servers"].as_array().unwrap();
        assert_eq!(servers[0]["tag"], DNS_TAG_DIRECT);
        assert_eq!(servers[1]["tag"], DNS_TAG_PROXY);
        assert!(servers.iter().all(|s| s.get("outboundTag").is_none()));
        assert_eq!(servers[0]["domains"][0], "geosite:ru");

        let rules = dns_routing_rules();
        assert_eq!(rules[0]["inboundTag"][0], DNS_TAG_DIRECT);
        assert_eq!(rules[0]["outboundTag"], "direct");
        assert_eq!(rules[1]["inboundTag"][0], DNS_TAG_PROXY);
        assert_eq!(rules[1]["outboundTag"], "proxy");
    }

    #[test]
    fn xray_version_parsing() {
        assert_eq!(parse_xray_version("Xray 25.6.8 (Xray, Penetrates Everything.)"), Some((25, 6, 8)));
        assert_eq!(parse_xray_version("Xray v26.1.23 (go1.25)"), Some((26, 1, 23)));
        assert_eq!(parse_xray_version("garbage"), None);
        assert!((26, 1, 12) < XRAY_MIN_VERSION && (26, 1, 13) >= XRAY_MIN_VERSION && (25, 6, 8) < XRAY_MIN_VERSION);
    }

    #[test]
    fn vpn_modes_get_a_local_dns_listener_routed_through_the_tunnel() {
        let inbound = vpn_mode_dns_inbound();
        assert_eq!(inbound["listen"], "127.0.0.1");
        assert_eq!(inbound["port"], 53);
        assert_eq!(inbound["protocol"], "dokodemo-door");
        assert_eq!(inbound["tag"], "dns-in");
        assert_eq!(inbound["settings"]["address"], VPN_MODE_DNS_UPSTREAM);
        let rule = vpn_mode_dns_rule();
        assert_eq!(rule["inboundTag"][0], "dns-in");
        assert_eq!(rule["outboundTag"], "proxy");
    }

    #[test]
    fn unsupported_transports_are_rejected_not_rewritten() {
        assert_eq!(vless_network("tcp"), Ok("tcp"));
        assert_eq!(vless_network(""), Ok("tcp"));
        assert_eq!(vless_network("xhttp"), Ok("xhttp"));
        assert_eq!(vless_network("splithttp"), Ok("xhttp"));
        for t in ["ws", "grpc", "httpupgrade", "kcp", "h2"] {
            let e = vless_network(t).unwrap_err();
            assert!(e.contains(t), "{}", e);
        }
    }

    #[test]
    fn kill_switch_failure_has_prefix_for_the_ui() {
        let e = enable_kill_switch(&["example.com".to_string()], "tun0").unwrap_err();
        assert!(e.starts_with(KS_FAILED_PREFIX), "{}", e);
    }
}
