//! Преобразование outbound'ов из JSON-подписки (формат Xray/v2rayNG) в обычные ссылки
//! `vless://`, `vmess://`, `trojan://`, `ss://`, которые дальше разбирает остальной код приложения.

use base64::{engine::general_purpose, Engine as _};
use serde_json::{json, Value};

const UNRESERVED: &[u8] = b"-._~";

/// Процентное кодирование для компонентов ссылки (userinfo, значения query, фрагмент).
pub fn pct_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || UNRESERVED.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Обратная операция: `%XX` -> байт. Некорректные последовательности остаются как есть.
pub fn pct_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn host_for_url(addr: &str) -> String {
    if addr.contains(':') && !addr.starts_with('[') {
        format!("[{}]", addr)
    } else {
        addr.to_string()
    }
}

fn s<'a>(v: &'a Value, ptr: &str) -> &'a str {
    v.pointer(ptr).and_then(|x| x.as_str()).unwrap_or("")
}

fn port_of(v: &Value, ptr: &str) -> u64 {
    match v.pointer(ptr) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(443),
        Some(Value::String(t)) => t.parse().unwrap_or(443),
        _ => 443,
    }
}

/// Параметры транспорта и безопасности общие для vless/trojan: собираем query-строку.
fn stream_query(out: &Value, include_flow: Option<&str>) -> Vec<(String, String)> {
    let stream = out.get("streamSettings").cloned().unwrap_or_else(|| json!({}));
    let network = stream.get("network").and_then(|x| x.as_str()).unwrap_or("tcp");
    let security = stream.get("security").and_then(|x| x.as_str()).unwrap_or("none");

    let mut q: Vec<(String, String)> = Vec::new();
    q.push(("type".into(), network.to_string()));
    q.push(("security".into(), security.to_string()));

    match security {
        "reality" => {
            q.push(("pbk".into(), s(&stream, "/realitySettings/publicKey").to_string()));
            q.push(("sni".into(), s(&stream, "/realitySettings/serverName").to_string()));
            q.push(("sid".into(), s(&stream, "/realitySettings/shortId").to_string()));
            let fp = s(&stream, "/realitySettings/fingerprint");
            q.push(("fp".into(), if fp.is_empty() { "firefox" } else { fp }.to_string()));
            let spx = s(&stream, "/realitySettings/spiderX");
            if !spx.is_empty() {
                q.push(("spx".into(), spx.to_string()));
            }
        }
        "tls" => {
            q.push(("sni".into(), s(&stream, "/tlsSettings/serverName").to_string()));
            let fp = s(&stream, "/tlsSettings/fingerprint");
            q.push(("fp".into(), if fp.is_empty() { "firefox" } else { fp }.to_string()));
        }
        _ => {}
    }

    if matches!(network, "xhttp" | "splithttp" | "httpupgrade") {
        let key = if network == "httpupgrade" { "httpupgradeSettings" } else { "xhttpSettings" };
        let path = s(&stream, &format!("/{}/path", key));
        let host = s(&stream, &format!("/{}/host", key));
        let mode = s(&stream, &format!("/{}/mode", key));
        if !path.is_empty() { q.push(("path".into(), path.to_string())); }
        if !host.is_empty() { q.push(("host".into(), host.to_string())); }
        if !mode.is_empty() { q.push(("mode".into(), mode.to_string())); }
    }

    if let Some(flow) = include_flow {
        if !flow.is_empty() {
            q.push(("flow".into(), flow.to_string()));
        }
    }
    q
}

fn join_query(q: &[(String, String)]) -> String {
    q.iter().map(|(k, v)| format!("{}={}", k, pct_encode(v))).collect::<Vec<_>>().join("&")
}

fn fragment(remarks: &str) -> String {
    pct_encode(remarks)
}

fn vless_link(out: &Value, remarks: &str) -> Option<String> {
    let address = s(out, "/settings/vnext/0/address");
    let id = s(out, "/settings/vnext/0/users/0/id");
    if address.is_empty() || id.is_empty() {
        return None;
    }
    let port = port_of(out, "/settings/vnext/0/port");
    let flow = s(out, "/settings/vnext/0/users/0/flow");
    let q = stream_query(out, Some(flow));
    Some(format!("vless://{}@{}:{}?{}#{}", pct_encode(id), host_for_url(address), port, join_query(&q), fragment(remarks)))
}

fn trojan_link(out: &Value, remarks: &str) -> Option<String> {
    let address = s(out, "/settings/servers/0/address");
    let password = s(out, "/settings/servers/0/password");
    if address.is_empty() || password.is_empty() {
        return None;
    }
    let port = port_of(out, "/settings/servers/0/port");
    let flow = s(out, "/settings/servers/0/flow");
    let q = stream_query(out, Some(flow));
    Some(format!("trojan://{}@{}:{}?{}#{}", pct_encode(password), host_for_url(address), port, join_query(&q), fragment(remarks)))
}

fn shadowsocks_link(out: &Value, remarks: &str) -> Option<String> {
    let address = s(out, "/settings/servers/0/address");
    let method = s(out, "/settings/servers/0/method");
    let password = s(out, "/settings/servers/0/password");
    if address.is_empty() || method.is_empty() {
        return None;
    }
    let port = port_of(out, "/settings/servers/0/port");
    let userinfo = general_purpose::URL_SAFE_NO_PAD.encode(format!("{}:{}", method, password));
    Some(format!("ss://{}@{}:{}#{}", userinfo, host_for_url(address), port, fragment(remarks)))
}

fn vmess_link(out: &Value, remarks: &str) -> Option<String> {
    let address = s(out, "/settings/vnext/0/address");
    let id = s(out, "/settings/vnext/0/users/0/id");
    if address.is_empty() || id.is_empty() {
        return None;
    }
    let port = port_of(out, "/settings/vnext/0/port");
    let aid = out.pointer("/settings/vnext/0/users/0/alterId").and_then(|x| x.as_u64()).unwrap_or(0);
    let scy = {
        let v = s(out, "/settings/vnext/0/users/0/security");
        if v.is_empty() { "auto" } else { v }
    };
    let stream = out.get("streamSettings").cloned().unwrap_or_else(|| json!({}));
    let net = stream.get("network").and_then(|x| x.as_str()).unwrap_or("tcp");
    let security = stream.get("security").and_then(|x| x.as_str()).unwrap_or("none");

    let (path, host) = match net {
        "ws" => (s(&stream, "/wsSettings/path").to_string(), s(&stream, "/wsSettings/headers/Host").to_string()),
        "grpc" => (s(&stream, "/grpcSettings/serviceName").to_string(), String::new()),
        "h2" | "http" => (
            s(&stream, "/httpSettings/path").to_string(),
            stream.pointer("/httpSettings/host/0").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        ),
        _ => (String::new(), String::new()),
    };
    let tls = if security == "tls" { "tls" } else { "" };
    let obj = json!({
        "v": "2", "ps": remarks, "add": address, "port": port.to_string(), "id": id,
        "aid": aid.to_string(), "scy": scy, "net": net, "type": "none",
        "host": host, "path": path, "tls": tls,
        "sni": s(&stream, "/tlsSettings/serverName"),
        "fp": s(&stream, "/tlsSettings/fingerprint"),
    });
    Some(format!("vmess://{}", general_purpose::STANDARD.encode(obj.to_string())))
}

/// Ссылка для первого подходящего прокси-outbound из списка (freedom/blackhole/dns пропускаются).
pub fn first_outbound_link(outbounds: &[Value], remarks: &str) -> Option<String> {
    for out in outbounds {
        let link = match out.get("protocol").and_then(|x| x.as_str()) {
            Some("vless") => vless_link(out, remarks),
            Some("trojan") => trojan_link(out, remarks),
            Some("shadowsocks") => shadowsocks_link(out, remarks),
            Some("vmess") => vmess_link(out, remarks),
            _ => None,
        };
        if link.is_some() {
            return link;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pct_roundtrip() {
        let raw = "a b/ü+%";
        assert_eq!(pct_decode(&pct_encode(raw)), raw);
        assert_eq!(pct_decode("100%"), "100%");
        assert_eq!(pct_decode("%zz%4"), "%zz%4");
    }

    #[test]
    fn vless_reality() {
        let out = json!({
            "protocol": "vless",
            "settings": { "vnext": [{ "address": "1.2.3.4", "port": 443, "users": [{ "id": "uuid", "flow": "xtls-rprx-vision" }] }] },
            "streamSettings": { "network": "tcp", "security": "reality",
                "realitySettings": { "publicKey": "PBK", "serverName": "example.com", "shortId": "ab", "fingerprint": "chrome" } }
        });
        let link = first_outbound_link(&[out], "My Server").unwrap();
        assert!(link.starts_with("vless://uuid@1.2.3.4:443?"));
        assert!(link.contains("pbk=PBK") && link.contains("sni=example.com") && link.contains("fp=chrome"));
        assert!(link.contains("flow=xtls-rprx-vision"));
        assert!(link.ends_with("#My%20Server"));
    }

    #[test]
    fn trojan_tls_ipv6() {
        let out = json!({
            "protocol": "trojan",
            "settings": { "servers": [{ "address": "2001:db8::1", "port": 8443, "password": "p@ss word" }] },
            "streamSettings": { "network": "tcp", "security": "tls", "tlsSettings": { "serverName": "t.example" } }
        });
        let link = first_outbound_link(&[out], "t").unwrap();
        assert!(link.starts_with("trojan://p%40ss%20word@[2001:db8::1]:8443?"));
        assert!(link.contains("sni=t.example"));
    }

    #[test]
    fn shadowsocks_and_vmess() {
        let ss = json!({ "protocol": "shadowsocks", "settings": { "servers": [{ "address": "h.example", "port": 8388, "method": "aes-256-gcm", "password": "pw" }] } });
        let link = first_outbound_link(&[ss], "s").unwrap();
        let body = link.trim_start_matches("ss://").split('@').next().unwrap().to_string();
        assert_eq!(String::from_utf8(general_purpose::URL_SAFE_NO_PAD.decode(body).unwrap()).unwrap(), "aes-256-gcm:pw");
        assert!(link.contains("@h.example:8388#s"));

        let vm = json!({ "protocol": "vmess",
            "settings": { "vnext": [{ "address": "v.example", "port": 443, "users": [{ "id": "uid", "alterId": 0, "security": "auto" }] }] },
            "streamSettings": { "network": "ws", "security": "tls", "wsSettings": { "path": "/w", "headers": { "Host": "h.example" } }, "tlsSettings": { "serverName": "h.example" } } });
        let link = first_outbound_link(&[vm], "v").unwrap();
        let decoded = general_purpose::STANDARD.decode(link.trim_start_matches("vmess://")).unwrap();
        let v: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(v["net"], "ws");
        assert_eq!(v["tls"], "tls");
        assert_eq!(v["path"], "/w");
    }

    #[test]
    fn skips_non_proxy_outbounds() {
        let outs = [json!({ "protocol": "freedom", "tag": "direct" }), json!({ "protocol": "blackhole" })];
        assert!(first_outbound_link(&outs, "x").is_none());
    }
}
