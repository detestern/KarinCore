// **********************************
// IMPORTS
// **********************************
use base64::{engine::general_purpose, Engine as _};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Mutex;
#[cfg(target_os = "android")]
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;
#[cfg(not(target_os = "android"))]
use tauri::{Manager, RunEvent};
use url::Url;

use tauri_plugin_karin_vpn::InstalledApp;
#[cfg(target_os = "android")]
use tauri_plugin_karin_vpn::SaveDocumentRequest;
#[cfg(target_os = "android")]
use tauri_plugin_karin_vpn::SecureStateRequest;
#[cfg(target_os = "android")]
use tauri_plugin_karin_vpn::{KarinVpnExt, StartRequest};

// **********************************
// STATE & AUTHENTICATION
// **********************************
struct ProxyState {
    auth_token: Mutex<Option<String>>,
}

const MAX_SECURE_STATE_BYTES: usize = 8 * 1024 * 1024;

fn validate_secure_state(content: &str) -> Result<(), String> {
    if content.len() > MAX_SECURE_STATE_BYTES {
        return Err("SECURE_STATE_TOO_LARGE".into());
    }
    serde_json::from_str::<Value>(content)
        .map(|_| ())
        .map_err(|_| "SECURE_STATE_INVALID_JSON".into())
}

fn is_forbidden_subscription_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn validate_subscription_url(input: &str) -> Result<Url, String> {
    let url = Url::parse(input).map_err(|_| "SUBSCRIPTION_URL_INVALID".to_string())?;
    if url.scheme() != "https" {
        return Err("SUBSCRIPTION_HTTPS_REQUIRED".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("SUBSCRIPTION_URL_CREDENTIALS_FORBIDDEN".into());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "SUBSCRIPTION_HOST_MISSING".to_string())?;
    if host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.ends_with(".local")
    {
        return Err("SUBSCRIPTION_PRIVATE_HOST_FORBIDDEN".into());
    }
    let literal_ip = match url.host() {
        Some(url::Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
        _ => None,
    };
    if literal_ip.is_some_and(is_forbidden_subscription_ip) {
        return Err("SUBSCRIPTION_PRIVATE_HOST_FORBIDDEN".into());
    }
    Ok(url)
}

#[cfg(not(target_os = "android"))]
async fn fetch_subscription_text(
    url: &str,
) -> Result<(reqwest::StatusCode, String, String, Option<String>), String> {
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    let mut current = validate_subscription_url(url)?;

    for redirects in 0..=5 {
        let host = current
            .host_str()
            .ok_or_else(|| "SUBSCRIPTION_HOST_MISSING".to_string())?
            .to_string();
        let port = current.port_or_known_default().unwrap_or(443);
        let is_domain = matches!(current.host(), Some(url::Host::Domain(_)));
        let addresses: Vec<std::net::SocketAddr> = match current.host() {
            Some(url::Host::Ipv4(ip)) => vec![std::net::SocketAddr::new(ip.into(), port)],
            Some(url::Host::Ipv6(ip)) => vec![std::net::SocketAddr::new(ip.into(), port)],
            _ => tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| format!("SUBSCRIPTION_DNS: {e}"))?
                .collect(),
        };
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|address| is_forbidden_subscription_ip(address.ip()))
        {
            return Err("SUBSCRIPTION_PRIVATE_HOST_FORBIDDEN".into());
        }

        // Pin the validated resolution into this one-request client. This closes
        // the DNS-rebinding gap between policy validation and the TCP connect.
        let mut client_builder = reqwest::Client::builder()
            .user_agent("KarinCore/0.1")
            .connect_timeout(std::time::Duration::from_secs(8))
            .timeout(std::time::Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none());
        if is_domain {
            client_builder = client_builder.resolve_to_addrs(&host, &addresses);
        }
        let client = client_builder
            .build()
            .map_err(|e| format!("Ошибка HTTP клиента: {e}"))?;

        let mut response = client.get(current.clone()).send().await.map_err(|e| {
            if e.is_timeout() {
                "SUBSCRIPTION_TIMEOUT: сервер подписки не ответил за 20 секунд".to_string()
            } else if e.is_connect() {
                format!("SUBSCRIPTION_CONNECT: не удалось подключиться к серверу подписки: {e}")
            } else {
                format!("SUBSCRIPTION_NETWORK: {e}")
            }
        })?;

        if response.status().is_redirection() {
            if redirects == 5 {
                return Err("SUBSCRIPTION_REDIRECT_LIMIT".into());
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| "SUBSCRIPTION_REDIRECT_INVALID".to_string())?;
            current = current
                .join(location)
                .map_err(|_| "SUBSCRIPTION_REDIRECT_INVALID".to_string())?;
            validate_subscription_url(current.as_str())?;
            continue;
        }

        if response
            .content_length()
            .is_some_and(|length| length > MAX_BYTES as u64)
        {
            return Err("SUBSCRIPTION_TOO_LARGE: ответ подписки превышает 8 МБ".into());
        }
        let status = response.status();
        let routing_header = response
            .headers()
            .get("routing")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| format!("SUBSCRIPTION_READ: {e}"))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_BYTES {
                return Err("SUBSCRIPTION_TOO_LARGE: ответ подписки превышает 8 МБ".into());
            }
            body.extend_from_slice(&chunk);
        }
        let text = String::from_utf8(body)
            .map_err(|_| "SUBSCRIPTION_ENCODING: ответ подписки должен быть UTF-8".to_string())?;
        return Ok((status, text, current.to_string(), routing_header));
    }

    Err("SUBSCRIPTION_REDIRECT_LIMIT".into())
}

#[cfg(target_os = "android")]
#[tauri::command]
fn save_secure_state(app: tauri::AppHandle, content: String) -> Result<(), String> {
    validate_secure_state(&content)?;
    app.karin_vpn()
        .save_secure_state(SecureStateRequest { content })
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "android")]
#[tauri::command]
fn load_secure_state(app: tauri::AppHandle) -> Result<Option<String>, String> {
    app.karin_vpn()
        .load_secure_state()
        .map(|result| result.content)
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "android"))]
fn secure_state_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;

    let directory = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    Ok(directory.join("profile-state.json"))
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn save_secure_state(app: tauri::AppHandle, content: String) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    validate_secure_state(&content)?;
    let path = secure_state_path(&app)?;
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = path.with_file_name(format!(".profile-state.{suffix}.tmp"));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        file.write_all(content.as_bytes())
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&temporary, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn load_secure_state(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let path = secure_state_path(&app)?;
    match std::fs::read_to_string(path) {
        Ok(content) => {
            validate_secure_state(&content)?;
            Ok(Some(content))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn generate_token() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("operating system CSPRNG unavailable");
    let encoded = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("karin_token_{encoded}")
}

// **********************************
// CORE HELPER FUNCTIONS
// **********************************
fn get_log_paths() -> (String, String) {
    #[cfg(not(target_os = "android"))]
    {
        (
            "/var/log/karin-proxy/error.log".to_string(),
            "/var/log/karin-proxy/access.log".to_string(),
        )
    }

    #[cfg(target_os = "android")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let log_dir = format!("{}/.local/share/karin-proxy", home);

        let _ = std::fs::create_dir_all(&log_dir);

        let err_log = format!("{}/error.log", log_dir);
        let acc_log = format!("{}/access.log", log_dir);

        if !std::path::Path::new(&err_log).exists() {
            let _ = std::fs::File::create(&err_log);
        }
        if !std::path::Path::new(&acc_log).exists() {
            let _ = std::fs::File::create(&acc_log);
        }

        (err_log, acc_log)
    }
}

#[cfg(not(target_os = "android"))]
fn run_privileged_helper(operation: &str, payload: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::process::Stdio;

    const ALLOWED: &[&str] = &[
        "install-xray",
        "install-openvpn",
        "install-wireguard",
        "install-resolv",
        "resolver-enable",
        "resolver-restore",
        "install-geosite",
        "install-geoip",
        "killswitch-allow",
        "killswitch-remove",
        "route-delete",
    ];
    if !ALLOWED.contains(&operation) {
        return Err("Unsupported privileged helper operation".into());
    }

    let mut child = std::process::Command::new("sudo")
        .args(["-n", "/usr/libexec/karincore-helper", operation])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or_else(|| "Unable to open helper stdin".to_string())?
        .write_all(payload)
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

#[cfg(target_os = "android")]
fn run_privileged_helper(_operation: &str, _payload: &[u8]) -> Result<(), String> {
    Err("Privileged desktop helper is unavailable on Android".into())
}

fn build_xray_rules(state: &Value, priority: Vec<String>) -> Value {
    if let Some(rules) = state.get("_providerRules").and_then(Value::as_array) {
        return Value::Array(rules.clone());
    }

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

                // Fields inside one Xray rule are AND-ed, so domains and IPs must be
                // separate rules (OR). Otherwise "domain:.pro" + "geoip:ru" in the same
                // zone would only match domains that ALSO resolve to a Russian IP.
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

fn build_runtime_routing(state: &Value, fallback_strategy: &str, rules: Vec<Value>) -> Value {
    let domain_strategy = state
        .get("_domainStrategy")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "AsIs" | "IPIfNonMatch" | "IPOnDemand"))
        .unwrap_or(fallback_strategy);
    let mut routing = json!({ "domainStrategy": domain_strategy, "rules": rules });
    if let Some(domain_matcher) = state
        .get("_domainMatcher")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "linear" | "hybrid"))
    {
        routing["domainMatcher"] = json!(domain_matcher);
    }
    routing
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
    routing_override: bool,
}

fn classify_outbound_zone(outbounds: &[Value], tag: &str) -> Option<&'static str> {
    match tag.to_ascii_lowercase().as_str() {
        "direct" | "freedom" | "bypass" => return Some("direct"),
        "block" | "blocked" | "reject" => return Some("block"),
        "proxy" | "proxied" => return Some("proxy"),
        _ => {}
    }

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
        json!({ "type": "geosite", "value": rest })
    } else if let Some(rest) = raw.strip_prefix("keyword:") {
        json!({ "type": "keyword", "value": rest })
    } else {
        json!({ "type": "domain", "value": raw })
    }
}

fn body_routing_header(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        let line = line.trim().trim_start_matches('#').trim();
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("routing") {
            return None;
        }

        let value = value.trim().trim_matches('"').trim();
        (!value.is_empty()).then_some(value)
    })
}

fn parse_v2raytun_routing_header(header: &str) -> Result<Value, String> {
    const MAX_ROUTING_BYTES: usize = 1024 * 1024;
    let value = header.trim().trim_matches('"').trim();
    let json_text = if value.starts_with('{') || value.starts_with('[') {
        value.to_string()
    } else {
        let encoded = value.strip_prefix("base64:").unwrap_or(value);
        let decoded = decode_base64_flexible(encoded).ok_or_else(|| {
            "SUBSCRIPTION_ROUTING_INVALID: routing header is not valid Base64".to_string()
        })?;
        if decoded.len() > MAX_ROUTING_BYTES {
            return Err("SUBSCRIPTION_ROUTING_TOO_LARGE: routing profile exceeds 1 MB".into());
        }
        decoded
    };

    if json_text.len() > MAX_ROUTING_BYTES {
        return Err("SUBSCRIPTION_ROUTING_TOO_LARGE: routing profile exceeds 1 MB".into());
    }

    let routing: Value = serde_json::from_str(&json_text)
        .map_err(|e| format!("SUBSCRIPTION_ROUTING_INVALID: {e}"))?;
    convert_routing_to_zones(&routing, &[], true).ok_or_else(|| {
        "SUBSCRIPTION_ROUTING_UNSUPPORTED: routing profile has no supported Direct, Proxy or Block rules".to_string()
    })
}

fn convert_routing_to_zones(
    routing: &Value,
    outbounds: &[Value],
    preserve_provider_config: bool,
) -> Option<Value> {
    let rules = routing
        .as_array()
        .or_else(|| routing.get("rules").and_then(Value::as_array))?;
    let mut zones = serde_json::Map::new();
    zones.insert("direct".to_string(), json!([]));
    zones.insert("proxy".to_string(), json!([]));
    zones.insert("block".to_string(), json!([]));
    let mut found_any = false;
    let mut provider_rules = Vec::new();

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

        let mut provider_rule = serde_json::Map::new();
        provider_rule.insert("type".into(), json!("field"));
        for key in [
            "domain",
            "ip",
            "port",
            "sourcePort",
            "network",
            "source",
            "user",
            "inboundTag",
            "protocol",
            "attrs",
        ] {
            if let Some(value) = rule.get(key) {
                provider_rule.insert(key.into(), value.clone());
            }
        }
        provider_rule.insert("outboundTag".into(), json!(zone_key));
        provider_rules.push(Value::Object(provider_rule));
        found_any = true;

        if let Some(domains) = rule.get("domain").and_then(|v| v.as_array()) {
            for d in domains {
                if let Some(s) = d.as_str() {
                    zone_arr.push(routing_rule_from_domain(s));
                    found_any = true;
                }
            }
        }
        if let Some(ips) = rule.get("ip").and_then(|v| v.as_array()) {
            for ip in ips {
                if let Some(s) = ip.as_str() {
                    zone_arr.push(json!({ "type": "ip", "value": s }));
                    found_any = true;
                }
            }
        }
    }

    if found_any {
        if preserve_provider_config {
            zones.insert("_providerRules".to_string(), Value::Array(provider_rules));
            if let Some(value) = routing.get("domainStrategy").and_then(Value::as_str) {
                zones.insert("_domainStrategy".to_string(), json!(value));
            }
            if let Some(value) = routing.get("domainMatcher").and_then(Value::as_str) {
                zones.insert("_domainMatcher".to_string(), json!(value));
            }
        }
        Some(Value::Object(zones))
    } else {
        None
    }
}

fn convert_dns_to_params(dns: &Value, outbounds: &[Value]) -> Option<Value> {
    let servers = dns.get("servers").and_then(|v| v.as_array())?;
    let mut domestic: Option<Value> = None;
    let mut remote: Option<Value> = None;

    for server in servers {
        let (address, tag) = if let Some(s) = server.as_str() {
            (s.to_string(), None)
        } else {
            let addr = server
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let tag = server
                .get("outboundTag")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            (addr, tag)
        };
        if address.is_empty() {
            continue;
        }

        let entry = if address.starts_with("https://") || address.starts_with("http://") {
            json!({ "type": "doh", "url": address, "ip": "" })
        } else {
            json!({ "type": "dou", "url": "", "ip": address })
        };

        let zone_key = tag
            .as_deref()
            .and_then(|t| classify_outbound_zone(outbounds, t));
        match zone_key {
            Some("direct") => {
                if domestic.is_none() {
                    domestic = Some(entry);
                }
            }
            Some("proxy") => {
                if remote.is_none() {
                    remote = Some(entry);
                }
            }
            _ => {
                if domestic.is_none() {
                    domestic = Some(entry);
                } else if remote.is_none() {
                    remote = Some(entry);
                }
            }
        }
    }

    if domestic.is_none() && remote.is_none() {
        None
    } else {
        Some(json!({ "domestic": domestic, "remote": remote }))
    }
}

// **********************************
// DNS
// **********************************
fn build_dns_server_entry(
    entry: &Value,
    outbound_tag: &str,
    hosts: &mut serde_json::Map<String, Value>,
) -> Value {
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
        json!({ "address": url, "outboundTag": outbound_tag })
    } else {
        json!({ "address": ip, "port": 53, "outboundTag": outbound_tag })
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

    let mut domestic_server = build_dns_server_entry(domestic_entry, "direct", &mut hosts);
    if !domestic_domains.is_empty() {
        if let Some(obj) = domestic_server.as_object_mut() {
            obj.insert("domains".to_string(), json!(domestic_domains));
        }
    }
    let remote_server = build_dns_server_entry(remote_entry, "proxy", &mut hosts);

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
        general_purpose::URL_SAFE_NO_PAD,
    ];
    for engine in &engines {
        if let Ok(bytes) = engine.decode(&cleaned) {
            if let Ok(utf8) = String::from_utf8(bytes) {
                return Some(utf8);
            }
        }
    }
    let mut padded = cleaned.clone();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    for engine in &engines {
        if let Ok(bytes) = engine.decode(&padded) {
            if let Ok(utf8) = String::from_utf8(bytes) {
                return Some(utf8);
            }
        }
    }
    None
}

async fn resolve_server_ips(server: &str, port: u16) -> (String, Vec<String>) {
    let mut resolved_ips: Vec<String> = vec![];
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        resolved_ips.push(ip.to_string());
    } else if let Ok(addrs) = tokio::net::lookup_host(format!("{}:{}", server, port)).await {
        for addr in addrs {
            resolved_ips.push(addr.ip().to_string());
        }
    }
    if resolved_ips.is_empty() {
        resolved_ips.push(server.to_string());
    }
    let out_addr = resolved_ips.first().unwrap_or(&server.to_string()).clone();
    (out_addr, resolved_ips)
}

async fn build_vless_or_trojan_outbound(
    link: &str,
    protocol: &str,
) -> Result<(Value, String, Vec<String>), String> {
    let parsed_url = Url::parse(link).map_err(|e| e.to_string())?;
    let server = parsed_url.host_str().unwrap_or("").to_string();
    let port = parsed_url.port().unwrap_or(443);
    let secret = parsed_url.username().to_string();

    let (out_addr, resolved_ips) = resolve_server_ips(&server, port).await;

    let mut pbk = String::new();
    let mut sid = String::new();
    let mut sni = String::new();
    let mut fp = String::from("firefox");
    let mut transport_type = String::from("tcp");
    let mut path = String::from("/");
    let mut host = String::new();
    let mut mode = String::from("auto");
    let mut spx = String::new();
    let mut security = String::from("none");
    let mut flow = String::new();

    for (k, v) in parsed_url.query_pairs() {
        match k.as_ref() {
            "pbk" => pbk = v.to_string(),
            "sid" => sid = v.to_string(),
            "sni" => sni = v.to_string(),
            "fp" => fp = v.to_string(),
            "type" => transport_type = v.to_string(),
            "path" => path = v.to_string(),
            "host" => host = v.to_string(),
            "mode" => mode = v.to_string(),
            "spx" => spx = v.to_string(),
            "security" => security = v.to_string(),
            "flow" => flow = v.to_string(),
            _ => {}
        }
    }
    if host.is_empty() {
        host = sni.clone();
    }

    let final_network = if transport_type == "xhttp" || transport_type == "httpupgrade" {
        "xhttp"
    } else {
        "tcp"
    };

    let mut stream_settings = serde_json::Map::new();
    stream_settings.insert("network".to_string(), json!(final_network));
    stream_settings.insert("security".to_string(), json!(security));
    stream_settings.insert("sockopt".to_string(), json!({ "mark": 255 }));

    if security == "reality" {
        stream_settings.insert("realitySettings".to_string(), json!({ "publicKey": pbk, "shortId": sid, "serverName": sni, "fingerprint": fp, "spiderX": spx }));
    } else if security == "tls" {
        stream_settings.insert(
            "tlsSettings".to_string(),
            json!({ "serverName": sni, "allowInsecure": false, "fingerprint": fp }),
        );
    }

    if final_network == "xhttp" {
        stream_settings.insert(
            "xhttpSettings".to_string(),
            json!({ "path": path, "host": host, "mode": mode }),
        );
    }

    let settings = if protocol == "trojan" {
        let mut server_obj = serde_json::Map::new();
        server_obj.insert("address".to_string(), json!(out_addr.clone()));
        server_obj.insert("port".to_string(), json!(port));
        server_obj.insert("password".to_string(), json!(secret));
        if !flow.is_empty() && (security == "reality" || security == "tls") {
            server_obj.insert("flow".to_string(), json!(flow));
        }
        json!({ "servers": [Value::Object(server_obj)] })
    } else {
        let mut user_obj = serde_json::Map::new();
        user_obj.insert("id".to_string(), json!(secret));
        user_obj.insert("encryption".to_string(), json!("none"));
        if !flow.is_empty() && (security == "reality" || security == "tls") {
            user_obj.insert("flow".to_string(), json!(flow));
        }
        json!({ "vnext": [{ "address": out_addr.clone(), "port": port, "users": [Value::Object(user_obj)] }] })
    };

    let outbound = json!({ "tag": "proxy", "protocol": protocol, "settings": settings, "streamSettings": Value::Object(stream_settings) });
    Ok((outbound, out_addr, resolved_ips))
}

async fn build_vmess_outbound(link: &str) -> Result<(Value, String, Vec<String>), String> {
    let b64_payload = link.trim_start_matches("vmess://");
    let decoded = decode_base64_flexible(b64_payload)
        .ok_or_else(|| "Не удалось декодировать VMess-ссылку".to_string())?;
    let v: Value =
        serde_json::from_str(&decoded).map_err(|e| format!("Некорректный VMess JSON: {}", e))?;

    let get_str = |key: &str| -> String {
        v.get(key)
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default()
    };
    let get_str_or_num = |key: &str| -> String {
        if let Some(x) = v.get(key) {
            if let Some(s) = x.as_str() {
                return s.to_string();
            }
            if let Some(n) = x.as_u64() {
                return n.to_string();
            }
        }
        String::new()
    };

    let server = get_str("add");
    let port: u16 = get_str_or_num("port").parse().unwrap_or(443);
    let id = get_str("id");
    let aid: u32 = get_str_or_num("aid").parse().unwrap_or(0);
    let scy = {
        let s = get_str("scy");
        if s.is_empty() {
            "auto".to_string()
        } else {
            s
        }
    };
    let net = {
        let s = get_str("net");
        if s.is_empty() {
            "tcp".to_string()
        } else {
            s
        }
    };
    let header_type = get_str("type");
    let host = get_str("host");
    let path = {
        let s = get_str("path");
        if s.is_empty() {
            "/".to_string()
        } else {
            s
        }
    };
    let tls = get_str("tls");
    let sni = {
        let s = get_str("sni");
        if s.is_empty() {
            host.clone()
        } else {
            s
        }
    };
    let fp = {
        let s = get_str("fp");
        if s.is_empty() {
            "firefox".to_string()
        } else {
            s
        }
    };

    if server.is_empty() || id.is_empty() {
        return Err("VMess-ссылка не содержит адрес сервера или id".into());
    }

    let (out_addr, resolved_ips) = resolve_server_ips(&server, port).await;

    let mut stream_settings = serde_json::Map::new();
    stream_settings.insert("network".to_string(), json!(net));
    stream_settings.insert("sockopt".to_string(), json!({ "mark": 255 }));

    match net.as_str() {
        "ws" => {
            stream_settings.insert(
                "wsSettings".to_string(),
                json!({ "path": path, "headers": { "Host": host } }),
            );
        }
        "grpc" => {
            stream_settings.insert(
                "grpcSettings".to_string(),
                json!({ "serviceName": path.trim_start_matches('/') }),
            );
        }
        "h2" | "http" => {
            stream_settings.insert(
                "httpSettings".to_string(),
                json!({ "path": path, "host": [host] }),
            );
        }
        _ => {
            if header_type == "http" {
                stream_settings.insert("tcpSettings".to_string(), json!({ "header": { "type": "http", "request": { "path": [path], "headers": { "Host": [host] } } } }));
            }
        }
    }

    if tls == "tls" {
        stream_settings.insert("security".to_string(), json!("tls"));
        stream_settings.insert(
            "tlsSettings".to_string(),
            json!({ "serverName": sni, "allowInsecure": false, "fingerprint": fp }),
        );
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
        let userinfo =
            decode_base64_flexible(userinfo_b64).unwrap_or_else(|| userinfo_b64.to_string());
        let (method, password) = split_shadowsocks_userinfo(&userinfo)
            .ok_or_else(|| "Некорректные учётные данные Shadowsocks".to_string())?;
        let mut hp = hostport.splitn(2, ':');
        let host = hp.next().unwrap_or("").to_string();
        let port: u16 = hp.next().unwrap_or("443").parse().unwrap_or(443);
        (method, password, host, port)
    } else {
        let decoded = decode_base64_flexible(body)
            .ok_or_else(|| "Не удалось декодировать Shadowsocks-ссылку".to_string())?;
        let at_pos = decoded
            .rfind('@')
            .ok_or_else(|| "Некорректный формат Shadowsocks-ссылки".to_string())?;
        let (cred, hostport) = decoded.split_at(at_pos);
        let hostport = &hostport[1..];
        let (method, password) = split_shadowsocks_userinfo(cred)
            .ok_or_else(|| "Некорректные учётные данные Shadowsocks".to_string())?;
        let mut hp = hostport.splitn(2, ':');
        let host = hp.next().unwrap_or("").to_string();
        let port: u16 = hp.next().unwrap_or("443").parse().unwrap_or(443);
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
    if link.starts_with("vmess://") {
        return build_vmess_outbound(link).await;
    }
    if link.starts_with("trojan://") {
        return build_vless_or_trojan_outbound(link, "trojan").await;
    }
    if link.starts_with("ss://") {
        return build_shadowsocks_outbound(link).await;
    }
    build_vless_or_trojan_outbound(link, "vless").await
}

async fn ensure_geo_files() -> Result<(), String> {
    let files = vec![
        (
            "geosite.dat",
            "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
        ),
        (
            "geoip.dat",
            "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
        ),
    ];

    for (filename, url) in files {
        let final_path = format!("/etc/karin-proxy/geo/{}", filename);
        if !Path::new(&final_path).exists() {
            let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
            let content = response.bytes().await.map_err(|e| e.to_string())?;

            let operation = if filename == "geosite.dat" {
                "install-geosite"
            } else {
                "install-geoip"
            };
            run_privileged_helper(operation, &content)?;
        }
    }

    Ok(())
}

// **********************************
// XRAY
// **********************************
const XRAY_MIN_VERSION: (u32, u32, u32) = (25, 0, 0);

fn find_xray_binary() -> Option<&'static str> {
    ["/usr/bin/xray", "/usr/local/bin/xray"]
        .into_iter()
        .find(|candidate| Path::new(candidate).exists())
}

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

async fn ensure_xray() -> Result<(), String> {
    let xray_path = match find_xray_binary() {
        Some(p) => p,
        None => {
            return Err(
                "Xray не установлен. Установите его через пакетный менеджер: \
                 sudo pacman -S xray (это зависимость пакета karincore-git, \
                 переустановка пакета тоже исправит это)."
                    .into(),
            );
        }
    };

    let output = std::process::Command::new(xray_path)
        .arg("version")
        .output()
        .map_err(|e| format!("Не удалось запустить xray для проверки версии: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    match parse_xray_version(&stdout) {
        Some(v) if v >= XRAY_MIN_VERSION => Ok(()),
        Some(v) => Err(format!(
            "Установленная версия Xray {}.{}.{} устарела. Обновите пакет: \
             sudo pacman -Syu xray (или пересоберите karincore-git).",
            v.0, v.1, v.2
        )),
        None => Ok(()),
    }
}

fn daemon_unit_installed() -> bool {
    std::process::Command::new("systemctl")
        .args([
            "list-unit-files",
            "--no-legend",
            "karin-proxy-daemon.service",
        ])
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

    let output = std::process::Command::new("sudo")
        .args([
            "/usr/bin/systemctl",
            "restart",
            "karin-proxy-daemon.service",
        ])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        return Ok(());
    }

    let log_text = std::process::Command::new("sudo")
        .args([
            "/usr/bin/journalctl",
            "-u",
            "karin-proxy-daemon.service",
            "-n",
            "15",
            "--no-pager",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|_| "не удалось прочитать журнал".to_string());

    Err(format!(
        "Ядро (karin-proxy-daemon.service) не запустилось. Лог:\n{}",
        log_text
    ))
}

// Ждём, пока Xray реально поднимет SOCKS/HTTP inbound на 2080, вместо
// фиксированной паузы — на "холодном" старте systemd 1.5с иногда не хватает,
// из-за чего первое подключение выглядело неудачным и требовало второго клика.
async fn wait_for_core_ready() -> bool {
    for _ in 0..15 {
        if tokio::net::TcpStream::connect("127.0.0.1:2080")
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    false
}

fn teardown_connections() {
    disable_kill_switch();
    std::process::Command::new("sudo")
        .args(["/usr/bin/systemctl", "stop", "karin-proxy-daemon.service"])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args(["-n", "/usr/libexec/karincore-helper", "openvpn-stop"])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args(["-n", "/usr/libexec/karincore-helper", "wireguard-down"])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args([
            "/usr/bin/iptables",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-o",
            "wg0",
            "-j",
            "MASQUERADE",
        ])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args([
            "/usr/bin/ip",
            "rule",
            "del",
            "fwmark",
            "111",
            "lookup",
            "111",
        ])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args([
            "/usr/bin/iptables",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-o",
            "tun-ovpn",
            "-j",
            "MASQUERADE",
        ])
        .output()
        .ok();
    let _ = run_privileged_helper("resolver-restore", &[]);
}

// Killswitch: разрешаем OUTPUT-трафик только через loopback, туннельный
// интерфейс и напрямую до самого VPN-сервера (нужно для хендшейка) — всё
// остальное блокируется правилом DROP в конце цепочки. Правила живут вне
// цикла route.sh up/down, поэтому переживают падение/автоперезапуск демона
// (systemd Restart=on-failure) — снимаются только явным отключением или
// новой попыткой подключения через teardown_connections().
static KILLSWITCH_SERVER_IP: Mutex<Option<String>> = Mutex::new(None);

fn enable_kill_switch(server_ip: &str, tun_iface: &str) {
    if server_ip.parse::<std::net::IpAddr>().is_err() {
        return;
    }
    if let Ok(mut value) = KILLSWITCH_SERVER_IP.lock() {
        *value = Some(server_ip.to_string());
    }
    std::process::Command::new("sudo")
        .args([
            "/usr/bin/iptables",
            "-A",
            "OUTPUT",
            "-o",
            "lo",
            "-j",
            "ACCEPT",
        ])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args([
            "/usr/bin/iptables",
            "-A",
            "OUTPUT",
            "-o",
            tun_iface,
            "-j",
            "ACCEPT",
        ])
        .output()
        .ok();
    run_privileged_helper("killswitch-allow", server_ip.as_bytes()).ok();
    std::process::Command::new("sudo")
        .args(["/usr/bin/iptables", "-A", "OUTPUT", "-j", "DROP"])
        .output()
        .ok();
}

fn disable_kill_switch() {
    // -D удаляет только первое совпадение за раз — на случай, если правила
    // накопились за несколько сессий (например, после аварийного завершения
    // приложения), чистим по несколько раз подряд, игнорируя ошибки "не найдено".
    for _ in 0..3 {
        std::process::Command::new("sudo")
            .args(["/usr/bin/iptables", "-D", "OUTPUT", "-j", "DROP"])
            .output()
            .ok();
        std::process::Command::new("sudo")
            .args([
                "/usr/bin/iptables",
                "-D",
                "OUTPUT",
                "-o",
                "lo",
                "-j",
                "ACCEPT",
            ])
            .output()
            .ok();
        for iface in ["tun0", "tun-ovpn", "wg0"] {
            std::process::Command::new("sudo")
                .args([
                    "/usr/bin/iptables",
                    "-D",
                    "OUTPUT",
                    "-o",
                    iface,
                    "-j",
                    "ACCEPT",
                ])
                .output()
                .ok();
        }
    }
    if let Ok(mut saved_ip) = KILLSWITCH_SERVER_IP.lock() {
        if let Some(ip) = saved_ip.take() {
            for _ in 0..3 {
                run_privileged_helper("killswitch-remove", ip.as_bytes()).ok();
            }
        }
    }
}

// **********************************
// OPENVPN CONFIG SANITIZATION
// **********************************
const OVPN_EXEC_DIRECTIVES: &[&str] = &[
    "up",
    "down",
    "up-restart",
    "up-delay",
    "down-pre",
    "plugin",
    "route-up",
    "route-pre-down",
    "ipchange",
    "client-connect",
    "client-disconnect",
    "client-crresponse",
    "tls-verify",
    "tls-export-cert",
    "learn-address",
    "auth-user-pass-verify",
    "setenv",
    "script-security",
];

fn sanitize_ovpn_config(raw: &str) -> String {
    raw.lines()
        .filter(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                return true;
            }
            let first_word = trimmed.split_whitespace().next().unwrap_or("");
            !OVPN_EXEC_DIRECTIVES
                .iter()
                .any(|d| d.eq_ignore_ascii_case(first_word))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// **********************************
// WIREGUARD CONFIG SANITIZATION
// **********************************
const WG_EXEC_DIRECTIVES: &[&str] = &["postup", "preup", "postdown", "predown"];

fn sanitize_wg_config(raw: &str) -> String {
    raw.lines()
        .filter(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return true;
            }
            let key = trimmed
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            !WG_EXEC_DIRECTIVES.iter().any(|d| *d == key)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(any(target_os = "android", test))]
#[derive(Default)]
struct AndroidWireGuardPeer {
    public_key: String,
    pre_shared_key: String,
    endpoint: String,
    keep_alive: u32,
    allowed_ips: Vec<String>,
}

#[cfg(any(target_os = "android", test))]
fn decode_wireguard_payload(payload: &str) -> Result<String, String> {
    let normalized = payload.trim().replace(' ', "+");
    let decoded = general_purpose::STANDARD
        .decode(&normalized)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(&normalized))
        .or_else(|_| general_purpose::URL_SAFE.decode(&normalized))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(&normalized))
        .map_err(|e| format!("Ошибка Base64 WireGuard payload: {}", e))?;

    String::from_utf8(decoded).map_err(|e| format!("Ошибка UTF-8 WireGuard payload: {}", e))
}

#[cfg(any(target_os = "android", test))]
fn build_android_wireguard_outbound(wg_link: &str) -> Result<Value, String> {
    let parsed_url =
        Url::parse(wg_link).map_err(|e| format!("Некорректная WireGuard ссылка: {}", e))?;
    let payload = parsed_url
        .query_pairs()
        .find_map(|(key, value)| (key == "payload").then(|| value.into_owned()))
        .ok_or_else(|| "В WireGuard ссылке отсутствует payload конфигурации".to_string())?;

    let raw_config = decode_wireguard_payload(&payload)?;
    let sanitized = sanitize_wg_config(&raw_config);

    let mut section = "";
    let mut secret_key = String::new();
    let mut addresses: Vec<String> = Vec::new();
    let mut remote_dns: Vec<String> = Vec::new();
    let mut mtu: i32 = 1420;
    let mut reserved: Vec<u8> = Vec::new();
    let mut peers: Vec<AndroidWireGuardPeer> = Vec::new();
    let mut current_peer: Option<AndroidWireGuardPeer> = None;

    for raw_line in sanitized.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            if let Some(peer) = current_peer.take() {
                peers.push(peer);
            }

            section = match line[1..line.len() - 1].trim().to_ascii_lowercase().as_str() {
                "interface" => "interface",
                "peer" => {
                    current_peer = Some(AndroidWireGuardPeer::default());
                    "peer"
                }
                _ => "",
            };
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value.trim();

        match section {
            "interface" => match key.as_str() {
                "privatekey" => secret_key = value.to_string(),
                "address" => {
                    addresses.extend(
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|item| !item.is_empty())
                            .map(|item| item.split('/').next().unwrap_or(item).trim().to_string()),
                    );
                }
                "dns" => {
                    remote_dns.extend(
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|item| item.parse::<std::net::IpAddr>().is_ok())
                            .map(ToString::to_string),
                    );
                }
                "mtu" => {
                    if let Ok(parsed) = value.parse::<i32>() {
                        mtu = parsed.clamp(576, 9000);
                    }
                }
                "reserved" => {
                    let bytes = value
                        .split(',')
                        .filter_map(|part| part.trim().parse::<u8>().ok())
                        .collect::<Vec<_>>();
                    if bytes.len() == 3 {
                        reserved = bytes;
                    }
                }
                _ => {}
            },
            "peer" => {
                let Some(peer) = current_peer.as_mut() else {
                    continue;
                };
                match key.as_str() {
                    "publickey" => peer.public_key = value.to_string(),
                    "presharedkey" => peer.pre_shared_key = value.to_string(),
                    "endpoint" => peer.endpoint = value.to_string(),
                    "persistentkeepalive" => {
                        peer.keep_alive = value.parse::<u32>().unwrap_or(0);
                    }
                    "allowedips" => {
                        peer.allowed_ips = value
                            .split(',')
                            .map(str::trim)
                            .filter(|item| !item.is_empty())
                            .map(ToString::to_string)
                            .collect();
                    }
                    "reserved" => {
                        let bytes = value
                            .split(',')
                            .filter_map(|part| part.trim().parse::<u8>().ok())
                            .collect::<Vec<_>>();
                        if bytes.len() == 3 {
                            reserved = bytes;
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    if let Some(peer) = current_peer.take() {
        peers.push(peer);
    }

    if secret_key.is_empty() {
        return Err("WireGuard config: отсутствует Interface.PrivateKey".into());
    }
    if addresses.is_empty() {
        return Err("WireGuard config: отсутствует Interface.Address".into());
    }
    if peers.is_empty() {
        return Err("WireGuard config: отсутствует Peer".into());
    }

    let peer_values = peers
        .into_iter()
        .map(|peer| {
            if peer.public_key.is_empty() {
                return Err("WireGuard config: отсутствует Peer.PublicKey".to_string());
            }
            if peer.endpoint.is_empty() {
                return Err("WireGuard config: отсутствует Peer.Endpoint".to_string());
            }

            let allowed_ips = if peer.allowed_ips.is_empty() {
                vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
            } else {
                peer.allowed_ips
            };

            let mut peer_json = json!({
                "publicKey": peer.public_key,
                "endpoint": peer.endpoint,
                "allowedIPs": allowed_ips,
                "keepAlive": peer.keep_alive
            });

            if !peer.pre_shared_key.is_empty() {
                peer_json["preSharedKey"] = json!(peer.pre_shared_key);
            }

            Ok(peer_json)
        })
        .collect::<Result<Vec<Value>, String>>()?;

    if remote_dns.is_empty() {
        remote_dns = vec!["1.1.1.1".into(), "1.0.0.1".into()];
    }

    let mut settings = json!({
        "secretKey": secret_key,
        "address": addresses,
        "peers": peer_values,
        "noKernelTun": true,
        "mtu": mtu,
        "remoteDNS": remote_dns
    });

    if reserved.len() == 3 {
        settings["reserved"] = json!(reserved);
    }

    Ok(json!({
        "tag": "proxy",
        "protocol": "wireguard",
        "settings": settings
    }))
}

// **********************************
// TAURI COMMANDS: PROXY & NETWORK MANAGEMENT
// **********************************
fn parse_subscription_content_with_routing(
    text: &str,
    http_routing_header: Option<&str>,
) -> Result<SubscriptionResult, String> {
    let mut links = Vec::new();
    let mut imported_routing: Option<Value> = None;
    let mut imported_dns: Option<Value> = None;
    let mut subscription_routing = http_routing_header.map(str::to_string);

    let parse_json = |json_str: &str,
                      out_links: &mut Vec<String>,
                      out_routing: &mut Option<Value>,
                      out_dns: &mut Option<Value>| {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
            let arr = if let Some(a) = json.as_array() {
                a.clone()
            } else {
                vec![json]
            };

            for item in arr {
                let remarks = item
                    .get("remarks")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Proxy");
                let outbounds_arr = item
                    .get("outbounds")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                if let Some(outbounds) = item.get("outbounds").and_then(|v| v.as_array()) {
                    for out in outbounds {
                        if out.get("protocol").and_then(|v| v.as_str()) == Some("vless") {
                            let address = out
                                .pointer("/settings/vnext/0/address")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let port = out
                                .pointer("/settings/vnext/0/port")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(443);
                            let id = out
                                .pointer("/settings/vnext/0/users/0/id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let flow = out
                                .pointer("/settings/vnext/0/users/0/flow")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            let stream = out.get("streamSettings");
                            let network = stream
                                .and_then(|v| v.pointer("/network"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("tcp");
                            let security = stream
                                .and_then(|v| v.pointer("/security"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("none");
                            let pbk = stream
                                .and_then(|v| v.pointer("/realitySettings/publicKey"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let sni = stream
                                .and_then(|v| v.pointer("/realitySettings/serverName"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let sid = stream
                                .and_then(|v| v.pointer("/realitySettings/shortId"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let fp = stream
                                .and_then(|v| v.pointer("/realitySettings/fingerprint"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("firefox");

                            let safe_remarks =
                                utf8_percent_encode(remarks, NON_ALPHANUMERIC).to_string();
                            let link = format!("vless://{}@{}:{}?type={}&security={}&pbk={}&sni={}&sid={}&fp={}&flow={}#{}",
                                id, address, port, network, security, pbk, sni, sid, fp, flow, safe_remarks
                            );
                            out_links.push(link);
                            break;
                        }
                    }
                }

                if out_routing.is_none() {
                    if let Some(routing) = item.get("routing") {
                        if let Some(converted) =
                            convert_routing_to_zones(routing, &outbounds_arr, false)
                        {
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
            if s.starts_with("vless://")
                || s.starts_with("vmess://")
                || s.starts_with("trojan://")
                || s.starts_with("ss://")
                || s.starts_with("wg://")
            {
                out_links.push(s.to_string());
            }
        }
    };

    parse_json(text, &mut links, &mut imported_routing, &mut imported_dns);
    if links.is_empty() {
        parse_plain(text, &mut links);
    }

    if links.is_empty() {
        let b64 = text.replace(['\n', '\r', ' ', '\t'], "");
        let engines = [
            general_purpose::STANDARD,
            general_purpose::STANDARD_NO_PAD,
            general_purpose::URL_SAFE,
            general_purpose::URL_SAFE_NO_PAD,
        ];

        let mut decoded_str = String::new();
        let mut decoded = false;

        for engine in &engines {
            if let Ok(bytes) = engine.decode(&b64) {
                if let Ok(utf8) = String::from_utf8(bytes) {
                    decoded_str = utf8;
                    decoded = true;
                    break;
                }
            }
        }

        if !decoded {
            let mut padded = b64.clone();
            while !padded.len().is_multiple_of(4) {
                padded.push('=');
            }
            for engine in &engines {
                if let Ok(bytes) = engine.decode(&padded) {
                    if let Ok(utf8) = String::from_utf8(bytes) {
                        decoded_str = utf8;
                        decoded = true;
                        break;
                    }
                }
            }
        }

        if decoded {
            if subscription_routing.is_none() {
                subscription_routing = body_routing_header(&decoded_str).map(str::to_string);
            }
            parse_json(
                &decoded_str,
                &mut links,
                &mut imported_routing,
                &mut imported_dns,
            );
            if links.is_empty() {
                parse_plain(&decoded_str, &mut links);
            }
        }
    }

    if links.is_empty() {
        return Err("Не удалось найти профили.\nВозможно формат не поддерживается.".into());
    }

    if subscription_routing.is_none() {
        subscription_routing = body_routing_header(text).map(str::to_string);
    }
    let routing_override = subscription_routing.is_some();
    if let Some(header) = subscription_routing {
        imported_routing = Some(parse_v2raytun_routing_header(&header)?);
    }

    Ok(SubscriptionResult {
        links,
        imported_routing,
        imported_dns,
        routing_override,
    })
}

#[cfg(test)]
fn parse_subscription_content(text: &str) -> Result<SubscriptionResult, String> {
    parse_subscription_content_with_routing(text, None)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
async fn fetch_subscription(url: String) -> Result<SubscriptionResult, String> {
    validate_subscription_url(&url)?;
    let mut current_url = url;
    let mut text = String::new();
    let mut routing_header = None;
    let mut attempts = 0;

    while attempts < 2 {
        let (status, fetched_text, final_url, fetched_routing) =
            fetch_subscription_text(&current_url).await?;
        text = fetched_text;
        current_url = final_url;
        if fetched_routing.is_some() {
            routing_header = fetched_routing;
        }

        if !status.is_success() {
            return Err(format!(
                "Сервер вернул ошибку {}: {}",
                status.as_u16(),
                text.chars().take(80).collect::<String>()
            ));
        }

        let clean_check = text.trim();
        if (clean_check.starts_with('{')
            || clean_check.starts_with('[')
            || clean_check.contains("\"outbounds\":"))
            && attempts == 0
        {
            current_url = if current_url.contains('?') {
                format!("{}&flag=v2ray", current_url)
            } else {
                format!("{}?flag=v2ray", current_url)
            };
            attempts += 1;
            continue;
        }
        break;
    }

    parse_subscription_content_with_routing(&text, routing_header.as_deref())
}

#[cfg(target_os = "android")]
#[tauri::command]
async fn fetch_subscription(
    app: tauri::AppHandle,
    url: String,
) -> Result<SubscriptionResult, String> {
    use tauri_plugin_karin_vpn::FetchTextRequest;

    validate_subscription_url(&url)?;
    let mut current_url = url;
    let mut routing_header = None;
    let mut attempts = 0;

    while attempts < 2 {
        validate_subscription_url(&current_url)?;
        let fetched = app
            .karin_vpn()
            .fetch_text(FetchTextRequest {
                url: current_url.clone(),
                timeout_ms: 20_000,
                max_bytes: 8 * 1024 * 1024,
            })
            .map_err(|e| e.to_string())?;

        validate_subscription_url(&fetched.final_url)?;
        if !(200..300).contains(&fetched.status) {
            return Err(format!(
                "Сервер вернул ошибку {}: {}",
                fetched.status,
                fetched.content.chars().take(80).collect::<String>()
            ));
        }

        if fetched.routing.is_some() {
            routing_header = fetched.routing.clone();
        }

        let clean_check = fetched.content.trim();
        if (clean_check.starts_with('{')
            || clean_check.starts_with('[')
            || clean_check.contains("\"outbounds\":"))
            && attempts == 0
        {
            current_url = if current_url.contains('?') {
                format!("{}&flag=v2ray", current_url)
            } else {
                format!("{}?flag=v2ray", current_url)
            };
            attempts += 1;
            continue;
        }

        return parse_subscription_content_with_routing(
            &fetched.content,
            routing_header.as_deref(),
        );
    }

    Err("SUBSCRIPTION_EMPTY: не удалось получить подписку".into())
}

#[allow(clippy::too_many_arguments)]
async fn start_openvpn_proxy(
    _state: State<'_, ProxyState>,
    ovpn_link: String,
    routing_state: serde_json::Value,
    default_outbound: String,
    _dns_params: serde_json::Value,
    allow_server_proxy: bool,
    zone_priority: Vec<String>,
    proxy_lan: bool,
    kill_switch: bool,
) -> Result<String, String> {
    let parsed_url = Url::parse(&ovpn_link).map_err(|e| e.to_string())?;

    let mut b64_payload = String::new();
    for (k, v) in parsed_url.query_pairs() {
        if k == "payload" {
            b64_payload = v.to_string();
        }
    }

    if b64_payload.is_empty() {
        return Err("Ошибка: В полученной ссылке отсутствует payload конфигурации".into());
    }

    let decoded_bytes = general_purpose::STANDARD
        .decode(&b64_payload)
        .map_err(|e| format!("Ошибка декодирования Base64: {}", e))?;
    let mut ovpn_config = String::from_utf8(decoded_bytes)
        .map_err(|e| format!("Ошибка UTF-8 при сборке конфигурации: {}", e))?;

    let mut resolved_ips_for_route_del: Vec<String> = vec![];
    for line in ovpn_config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("remote ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let host = parts[1];
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    resolved_ips_for_route_del.push(ip.to_string());
                } else if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", host)).await {
                    for addr in addrs {
                        resolved_ips_for_route_del.push(addr.ip().to_string());
                    }
                }
            }
        }
    }

    ovpn_config = sanitize_ovpn_config(&ovpn_config);

    ovpn_config.push_str("\npull-filter ignore \"redirect-gateway\"\npull-filter ignore \"dhcp-option DNS\"\npull-filter ignore \"tun-mtu\"\ntun-mtu 1360\nmssfix 1320\ndev tun-ovpn\nmark 255\n");

    run_privileged_helper("install-openvpn", ovpn_config.as_bytes())
        .map_err(|e| format!("Нет прав на запись конфигурации OpenVPN: {e}"))?;

    let vpn_dns_content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
    run_privileged_helper("install-resolv", vpn_dns_content.as_bytes())?;

    run_privileged_helper("resolver-enable", &[])?;

    std::process::Command::new("sudo")
        .args(["/usr/bin/systemctl", "stop", "karin-proxy-daemon.service"])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args(["-n", "/usr/libexec/karincore-helper", "openvpn-stop"])
        .output()
        .ok();

    let mut child = tokio::process::Command::new("sudo")
        .args(["-n", "/usr/libexec/karincore-helper", "openvpn-start"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Не удалось запустить процесс OpenVPN: {}", e))?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (err_log, _) = get_log_paths();
    let err_log_stdout = err_log.clone();
    let err_log_stderr = err_log.clone();

    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut reader = tokio::io::BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if let Ok(mut file) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&err_log_stdout)
                .await
            {
                use tokio::io::AsyncWriteExt;
                let _ = file.write_all(format!("{}\n", line).as_bytes()).await;
            }
        }
    });

    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut reader = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if let Ok(mut file) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&err_log_stderr)
                .await
            {
                use tokio::io::AsyncWriteExt;
                let _ = file.write_all(format!("{}\n", line).as_bytes()).await;
            }
        }
    });

    let mut attempts = 0;
    while attempts < 20 {
        if std::path::Path::new("/sys/class/net/tun-ovpn").exists() {
            std::process::Command::new("sudo")
                .args([
                    "/usr/bin/ip",
                    "rule",
                    "del",
                    "fwmark",
                    "111",
                    "lookup",
                    "111",
                ])
                .output()
                .ok();
            std::process::Command::new("sudo")
                .args([
                    "/usr/bin/ip",
                    "route",
                    "add",
                    "default",
                    "dev",
                    "tun-ovpn",
                    "table",
                    "111",
                ])
                .output()
                .ok();
            std::process::Command::new("sudo")
                .args([
                    "/usr/bin/ip",
                    "rule",
                    "add",
                    "fwmark",
                    "111",
                    "lookup",
                    "111",
                ])
                .output()
                .ok();
            std::process::Command::new("sudo")
                .args([
                    "/usr/bin/sysctl",
                    "-w",
                    "net.ipv4.conf.tun-ovpn.rp_filter=0",
                ])
                .output()
                .ok();
            std::process::Command::new("sudo")
                .args(["/usr/bin/sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"])
                .output()
                .ok();
            std::process::Command::new("sudo")
                .args([
                    "/usr/bin/iptables",
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-o",
                    "tun-ovpn",
                    "-j",
                    "MASQUERADE",
                ])
                .output()
                .ok();
            std::process::Command::new("sudo")
                .args([
                    "/usr/bin/iptables",
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    "tun-ovpn",
                    "-j",
                    "MASQUERADE",
                ])
                .output()
                .ok();
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        attempts += 1;
    }

    if attempts >= 20 {
        teardown_connections();
        return Err("Таймаут: сервер OpenVPN не отвечает".into());
    }

    let dynamic_rules = build_xray_rules(&routing_state, zone_priority);

    let mut all_rules = vec![];
    all_rules.push(json!({ "type": "field", "inboundTag": ["ping-in"], "outboundTag": "proxy" }));
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
    if let Some(rules_array) = dynamic_rules.as_array() {
        all_rules.extend(rules_array.clone());
    }
    all_rules
        .push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": default_outbound }));
    let runtime_routing = build_runtime_routing(&routing_state, "AsIs", all_rules);

    let (err_log, acc_log) = get_log_paths();

    let config = serde_json::json!({
        "log": { "loglevel": "debug", "access": acc_log, "error": err_log },
        "routing": runtime_routing,
        "inbounds": [
            { "port": 2080, "listen": "127.0.0.1", "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": "openvpn_mode" } ] } },
            { "tag": "tun-in", "port": 2081, "listen": "127.0.0.1", "protocol": "tun", "settings": { "name": "tun0", "mtu": 1500, "gateway": ["172.19.0.1/30"] }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] } },
            { "tag": "ping-in", "listen": "127.0.0.1", "port": 2082, "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": "openvpn_mode" } ] } }
        ],
        "outbounds": [
            { "tag": "proxy", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 111, "interface": "tun-ovpn" } } },
            { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 255 } } },
            { "tag": "block", "protocol": "blackhole" }
        ]
    });

    run_privileged_helper("install-xray", config.to_string().as_bytes())
        .map_err(|e| format!("Нет прав на обновление конфигурации Xray: {e}"))?;

    if let Err(e) = restart_core_daemon() {
        teardown_connections();
        return Err(e);
    }

    if let Ok(mut guard) = _state.auth_token.lock() {
        *guard = Some("openvpn_mode".to_string());
    }
    if !wait_for_core_ready().await {
        teardown_connections();
        return Err(
            "Ядро не успело подняться (порт 2080 не отвечает). Попробуйте подключиться ещё раз."
                .into(),
        );
    }

    if kill_switch {
        if let Some(ip) = resolved_ips_for_route_del.first() {
            enable_kill_switch(ip, "tun-ovpn");
        }
    }

    if allow_server_proxy && !resolved_ips_for_route_del.is_empty() {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            for ip in resolved_ips_for_route_del {
                run_privileged_helper("route-delete", ip.as_bytes()).ok();
            }
        });
    }

    Ok("OK".into())
}

#[allow(clippy::too_many_arguments)]
async fn start_wireguard_proxy(
    _state: State<'_, ProxyState>,
    wg_link: String,
    routing_state: serde_json::Value,
    default_outbound: String,
    _dns_params: serde_json::Value,
    allow_server_proxy: bool,
    zone_priority: Vec<String>,
    proxy_lan: bool,
    kill_switch: bool,
) -> Result<String, String> {
    let parsed_url = Url::parse(&wg_link).map_err(|e| e.to_string())?;

    let mut b64_payload = String::new();
    for (k, v) in parsed_url.query_pairs() {
        if k == "payload" {
            b64_payload = v.to_string();
        }
    }
    if b64_payload.is_empty() {
        return Err("Ошибка: В полученной ссылке отсутствует payload конфигурации".into());
    }

    let decoded_bytes = general_purpose::STANDARD
        .decode(&b64_payload)
        .map_err(|e| format!("Ошибка Base64: {}", e))?;
    let raw_conf = String::from_utf8(decoded_bytes).map_err(|e| format!("Ошибка UTF-8: {}", e))?;
    let original_conf = sanitize_wg_config(&raw_conf);

    let mut resolved_ips_for_route_del: Vec<String> = vec![];
    let mut modified_conf = String::new();

    for line in original_conf.lines() {
        let trimmed = line.trim();
        if trimmed.to_lowercase().starts_with("dns") {
            continue;
        }

        if trimmed.to_lowercase().starts_with("endpoint") {
            let parts: Vec<&str> = trimmed.split('=').collect();
            if parts.len() >= 2 {
                let endpoint = parts[1].trim();
                let host = endpoint
                    .rsplit_once(':')
                    .map(|(h, _)| h)
                    .unwrap_or(endpoint);
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    resolved_ips_for_route_del.push(ip.to_string());
                } else if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", host)).await {
                    for addr in addrs {
                        resolved_ips_for_route_del.push(addr.ip().to_string());
                    }
                }
            }
        }

        modified_conf.push_str(line);
        modified_conf.push('\n');

        if trimmed.to_lowercase() == "[interface]" {
            modified_conf.push_str("Table = off\nFwMark = 255\n");
        }
    }

    run_privileged_helper("install-wireguard", modified_conf.as_bytes())
        .map_err(|e| format!("Нет прав на запись конфигурации WireGuard: {e}"))?;

    let vpn_dns_content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
    run_privileged_helper("install-resolv", vpn_dns_content.as_bytes())?;
    run_privileged_helper("resolver-enable", &[])?;

    std::process::Command::new("sudo")
        .args(["/usr/bin/systemctl", "stop", "karin-proxy-daemon.service"])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args(["-n", "/usr/libexec/karincore-helper", "wireguard-down"])
        .output()
        .ok();

    let output = std::process::Command::new("sudo")
        .args(["-n", "/usr/libexec/karincore-helper", "wireguard-up"])
        .output()
        .map_err(|e| format!("Не удалось запустить wg-quick: {}", e))?;

    let (err_log, _) = get_log_paths();

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&err_log)
    {
        use std::io::Write;
        let _ = writeln!(file, "[WireGuard] Инициализация интерфейса wg0...");
        if !output.stdout.is_empty() {
            let _ = writeln!(file, "{}", String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            let _ = writeln!(file, "{}", String::from_utf8_lossy(&output.stderr));
        }
    }

    if !output.status.success() {
        teardown_connections();
        return Err(format!(
            "Ошибка WireGuard:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    std::process::Command::new("sudo")
        .args([
            "/usr/bin/ip",
            "rule",
            "del",
            "fwmark",
            "111",
            "lookup",
            "111",
        ])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args([
            "/usr/bin/ip",
            "route",
            "add",
            "default",
            "dev",
            "wg0",
            "table",
            "111",
        ])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args([
            "/usr/bin/ip",
            "rule",
            "add",
            "fwmark",
            "111",
            "lookup",
            "111",
        ])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args(["/usr/bin/sysctl", "-w", "net.ipv4.conf.wg0.rp_filter=0"])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args(["/usr/bin/sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args([
            "/usr/bin/iptables",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-o",
            "wg0",
            "-j",
            "MASQUERADE",
        ])
        .output()
        .ok();
    std::process::Command::new("sudo")
        .args([
            "/usr/bin/iptables",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            "wg0",
            "-j",
            "MASQUERADE",
        ])
        .output()
        .ok();

    let log_path_clone = err_log.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3));
        loop {
            interval.tick().await;
            if !std::path::Path::new("/sys/class/net/wg0").exists() {
                break;
            }
            let wg_status = std::process::Command::new("sudo")
                .args(["/usr/bin/wg", "show", "wg0"])
                .output();
            if let Ok(out) = wg_status {
                if out.status.success() {
                    let status_str = String::from_utf8_lossy(&out.stdout);
                    let mut log_lines = Vec::new();
                    for line in status_str.lines() {
                        if line.contains("latest handshake:")
                            || line.contains("transfer:")
                            || line.contains("endpoint:")
                        {
                            log_lines.push(line.trim().to_string());
                        }
                    }
                    if !log_lines.is_empty() {
                        if let Ok(mut file) = tokio::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&log_path_clone)
                            .await
                        {
                            use tokio::io::AsyncWriteExt;
                            let _ = file
                                .write_all(
                                    format!("[WireGuard Status] {}\n", log_lines.join(" | "))
                                        .as_bytes(),
                                )
                                .await;
                        }
                    }
                }
            }
        }
    });

    let dynamic_rules = build_xray_rules(&routing_state, zone_priority);

    let mut all_rules = vec![];
    all_rules.push(json!({ "type": "field", "inboundTag": ["ping-in"], "outboundTag": "proxy" }));
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
    if let Some(rules_array) = dynamic_rules.as_array() {
        all_rules.extend(rules_array.clone());
    }
    all_rules
        .push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": default_outbound }));
    let runtime_routing = build_runtime_routing(&routing_state, "AsIs", all_rules);

    let (err_log, acc_log) = get_log_paths();

    let config = serde_json::json!({
        "log": { "loglevel": "debug", "access": acc_log, "error": err_log },
        "routing": runtime_routing,
        "inbounds": [
            { "port": 2080, "listen": "127.0.0.1", "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": "wireguard_mode" } ] } },
            { "tag": "tun-in", "port": 2081, "listen": "127.0.0.1", "protocol": "tun", "settings": { "name": "tun0", "mtu": 1420, "gateway": ["172.19.0.1/30"] }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] } },
            { "tag": "ping-in", "listen": "127.0.0.1", "port": 2082, "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": "wireguard_mode" } ] } }
        ],
        "outbounds": [
            { "tag": "proxy", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 111, "interface": "wg0" } } },
            { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 255 } } },
            { "tag": "block", "protocol": "blackhole" }
        ]
    });

    run_privileged_helper("install-xray", config.to_string().as_bytes())
        .map_err(|e| format!("Нет прав на обновление конфигурации Xray: {e}"))?;

    if let Err(e) = restart_core_daemon() {
        teardown_connections();
        return Err(e);
    }

    if let Ok(mut guard) = _state.auth_token.lock() {
        *guard = Some("wireguard_mode".to_string());
    }
    if !wait_for_core_ready().await {
        teardown_connections();
        return Err(
            "Ядро не успело подняться (порт 2080 не отвечает). Попробуйте подключиться ещё раз."
                .into(),
        );
    }

    if kill_switch {
        if let Some(ip) = resolved_ips_for_route_del.first() {
            enable_kill_switch(ip, "wg0");
        }
    }

    if allow_server_proxy && !resolved_ips_for_route_del.is_empty() {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            for ip in resolved_ips_for_route_del {
                run_privileged_helper("route-delete", ip.as_bytes()).ok();
            }
        });
    }

    Ok("OK".into())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn start_proxy(
    _state: State<'_, ProxyState>,
    vless_link: String,
    routing_state: serde_json::Value,
    default_outbound: String,
    dns_params: serde_json::Value,
    allow_server_proxy: bool,
    zone_priority: Vec<String>,
    proxy_lan: bool,
    kill_switch: bool,
) -> Result<String, String> {
    teardown_connections();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    if vless_link.starts_with("ovpn://") {
        return start_openvpn_proxy(
            _state,
            vless_link,
            routing_state,
            default_outbound,
            dns_params,
            allow_server_proxy,
            zone_priority,
            proxy_lan,
            kill_switch,
        )
        .await;
    }

    if vless_link.starts_with("wg://") {
        return start_wireguard_proxy(
            _state,
            vless_link,
            routing_state,
            default_outbound,
            dns_params,
            allow_server_proxy,
            zone_priority,
            proxy_lan,
            kill_switch,
        )
        .await;
    }

    let token = generate_token();
    if let Ok(mut guard) = _state.auth_token.lock() {
        *guard = Some(token.clone());
    }

    let (proxy_outbound, out_addr, resolved_ips) = build_proxy_outbound(&vless_link).await?;

    let dns_config = build_dns_config(&dns_params, &routing_state);
    let dynamic_rules = build_xray_rules(&routing_state, zone_priority);

    let mut all_rules = vec![];
    all_rules.push(json!({ "type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out" }));
    all_rules.push(json!({ "type": "field", "inboundTag": ["ping-in"], "outboundTag": "proxy" }));
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
    if let Some(rules_array) = dynamic_rules.as_array() {
        all_rules.extend(rules_array.clone());
    }
    all_rules
        .push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": default_outbound }));
    let runtime_routing = build_runtime_routing(&routing_state, "IPIfNonMatch", all_rules);

    let (err_log, acc_log) = get_log_paths();

    let config = serde_json::json!({
        "log": { "loglevel": "debug", "access": acc_log, "error": err_log },
        "dns": dns_config,
        "routing": runtime_routing,
        "inbounds": [
            { "port": 2080, "listen": "127.0.0.1", "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": token } ] } },
            { "tag": "tun-in", "port": 2081, "listen": "127.0.0.1", "protocol": "tun", "settings": { "name": "tun0", "mtu": 1500, "gateway": ["172.19.0.1/30"] }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] } },
            { "tag": "dns-in", "listen": "127.0.0.1", "port": 53, "protocol": "dokodemo-door", "settings": { "address": "1.1.1.1", "port": 53, "network": "udp" } },
            { "tag": "ping-in", "listen": "127.0.0.1", "port": 2082, "protocol": "mixed", "settings": { "accounts": [ { "user": "karin", "pass": token } ] } }
        ],
        "outbounds": [
            proxy_outbound,
            { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 255 } } },
            { "tag": "block", "protocol": "blackhole" },
            { "tag": "dns-out", "protocol": "dns" }
        ]
    });

    run_privileged_helper("install-xray", config.to_string().as_bytes())
        .map_err(|e| format!("Нет прав на обновление конфигурации Xray: {e}"))?;

    let rotate_if_needed = |path: &str| {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > 5 * 1024 * 1024 {
                let _ = std::fs::write(path, "");
            }
        }
    };
    rotate_if_needed(&err_log);
    rotate_if_needed(&acc_log);
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&err_log);
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&acc_log);

    if let Err(e) = restart_core_daemon() {
        teardown_connections();
        return Err(e);
    }
    if !wait_for_core_ready().await {
        teardown_connections();
        return Err(
            "Ядро не успело подняться (порт 2080 не отвечает). Попробуйте подключиться ещё раз."
                .into(),
        );
    }
    if kill_switch {
        enable_kill_switch(&out_addr, "tun0");
    }
    if allow_server_proxy {
        let ips_to_delete = resolved_ips.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            for ip in ips_to_delete {
                run_privileged_helper("route-delete", ip.as_bytes()).ok();
            }
        });
    }

    Ok("OK".into())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn stop_proxy(_state: State<'_, ProxyState>) -> Result<String, String> {
    if let Ok(mut guard) = _state.auth_token.lock() {
        *guard = None;
    }
    teardown_connections();
    Ok("Остановлено".into())
}

// **********************************
// TAURI COMMANDS: UTILITIES & NETWORK
// **********************************
fn build_probe_client(state: &State<'_, ProxyState>) -> Result<reqwest::Client, String> {
    let token = {
        let guard = state
            .auth_token
            .lock()
            .map_err(|_| "VPN proxy state is unavailable".to_string())?;
        guard
            .clone()
            .ok_or_else(|| "VPN proxy is not ready".to_string())?
    };

    let proxy = reqwest::Proxy::all("http://127.0.0.1:2082")
        .map_err(|e| e.to_string())?
        .basic_auth("karin", &token);
    reqwest::Client::builder()
        .proxy(proxy)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())
}

async fn probe_proxy_text(state: &State<'_, ProxyState>, url: &str) -> Result<String, String> {
    let client = build_probe_client(state)?;
    let mut last_error = String::new();

    for attempt in 0..4 {
        match client.get(url).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    return Err(format!("HTTP {}", response.status()));
                }

                return response
                    .text()
                    .await
                    .map(|text| text.trim().to_string())
                    .map_err(|e| format!("Ошибка чтения ответа: {}", e));
            }
            Err(error) => {
                let retryable = error.is_connect();
                last_error = error.to_string();
                if !retryable {
                    return Err(format!("Ошибка сети: {last_error}"));
                }
            }
        }

        if attempt < 3 {
            tokio::time::sleep(std::time::Duration::from_millis(250 * (attempt + 1))).await;
        }
    }

    Err(format!("Ошибка сети: {last_error}"))
}

fn validate_probe_ip(value: String) -> Result<String, String> {
    value
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| "Сервис проверки вернул некорректный IP".to_string())
}

#[tauri::command]
async fn get_vpn_ip(state: State<'_, ProxyState>) -> Result<String, String> {
    #[cfg(target_os = "android")]
    let url = "http://api.ipify.org";
    #[cfg(not(target_os = "android"))]
    let url = "https://api.ipify.org";

    validate_probe_ip(probe_proxy_text(&state, url).await?)
}

#[tauri::command]
async fn get_vpn_ipv4(state: State<'_, ProxyState>) -> Result<String, String> {
    #[cfg(target_os = "android")]
    let url = "http://api4.ipify.org";
    #[cfg(not(target_os = "android"))]
    let url = "https://api4.ipify.org";

    validate_probe_ip(probe_proxy_text(&state, url).await?)
}

#[tauri::command]
async fn get_vpn_ipv6(state: State<'_, ProxyState>) -> Result<String, String> {
    #[cfg(target_os = "android")]
    let url = "http://api6.ipify.org";
    #[cfg(not(target_os = "android"))]
    let url = "https://api6.ipify.org";

    validate_probe_ip(probe_proxy_text(&state, url).await?)
}

#[tauri::command]
async fn check_ping(state: State<'_, ProxyState>) -> Result<String, String> {
    let client = build_probe_client(&state)?;
    let start = std::time::Instant::now();
    #[cfg(target_os = "android")]
    let url = "http://cp.cloudflare.com/generate_204";
    #[cfg(not(target_os = "android"))]
    let url = "https://cp.cloudflare.com/generate_204";

    let mut response = None;
    let mut last_error = String::new();
    for attempt in 0..4 {
        match client.get(url).send().await {
            Ok(result) => {
                response = Some(result);
                break;
            }
            Err(error) => {
                let retryable = error.is_connect();
                last_error = error.to_string();
                if !retryable {
                    return Err(format!("Ошибка сети: {last_error}"));
                }
            }
        }

        if attempt < 3 {
            tokio::time::sleep(std::time::Duration::from_millis(250 * (attempt + 1))).await;
        }
    }
    let response = response.ok_or_else(|| format!("Ошибка сети: {last_error}"))?;

    if !response.status().is_success() && response.status().as_u16() != 204 {
        return Err(format!("HTTP {}", response.status()));
    }

    Ok(format!("{} ms", start.elapsed().as_millis()))
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn open_browser(url: String) -> Result<(), String> {
    let parsed = Url::parse(&url).map_err(|_| "BROWSER_URL_INVALID".to_string())?;
    if parsed.scheme() != "https" || parsed.host_str() != Some("github.com") {
        return Err("BROWSER_URL_FORBIDDEN".into());
    }
    std::process::Command::new("xdg-open")
        .arg(parsed.as_str())
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "android"))]
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
                return Ok(
                    "Ожидание логов (Прокси работает, ожидаем сетевой трафик)...".to_string(),
                );
            }
            let lines: Vec<&str> = content.lines().collect();
            let last_lines = if lines.len() > 50 {
                &lines[lines.len() - 50..]
            } else {
                &lines[..]
            };
            Ok(last_lines.join("\n"))
        }
        Err(e) => Ok(format!(
            "Ошибка чтения логов: {}\nУбедитесь, что прокси запущен.",
            e
        )),
    }
}

#[tauri::command]
fn get_geosite_list() -> Vec<String> {
    vec![
        "google",
        "youtube",
        "telegram",
        "vk",
        "yandex",
        "mailru",
        "github",
        "netflix",
        "spotify",
        "instagram",
        "twitter",
        "facebook",
        "tiktok",
        "apple",
        "microsoft",
        "amazon",
        "discord",
        "reddit",
        "twitch",
        "ru",
        "cn",
        "us",
        "geolocation-!cn",
        "geolocation-!ru",
        "category-ads-all",
        "category-porn",
        "category-games",
        "private",
        "speedtest",
        "openai",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn clear_logs() -> Result<String, String> {
    let (err_log, acc_log) = get_log_paths();
    let _ = std::fs::write(&err_log, "");
    let _ = std::fs::write(&acc_log, "");
    Ok("Очищено".into())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
async fn export_profile(filename: String, content: String) -> Result<String, String> {
    let result = tokio::task::spawn_blocking(move || {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Экспорт профиля маршрутизации")
            .set_file_name(&filename)
            .add_filter("JSON Config", &["json"])
            .save_file()
        {
            std::fs::write(&path, content).map_err(|e| format!("Ошибка записи: {}", e))?;
            Ok(format!("Сохранено в {}", path.display()))
        } else {
            Err("Отменено".to_string())
        }
    })
    .await
    .map_err(|e| format!("Ошибка потока: {}", e))?;
    result
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn minimize_window(window: tauri::Window) {
    let _ = window.minimize();
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn maximize_window(window: tauri::Window) {
    if let Ok(maximized) = window.is_maximized() {
        if maximized {
            let _ = window.unmaximize();
        } else {
            let _ = window.maximize();
        }
    }
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn close_window(_window: tauri::Window, _state: State<'_, ProxyState>) {
    if let Ok(mut guard) = _state.auth_token.lock() {
        *guard = None;
    }
    teardown_connections();
    std::process::exit(0);
}

#[cfg(target_os = "android")]
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn start_proxy(
    app: tauri::AppHandle,
    state: State<'_, ProxyState>,
    vless_link: String,
    routing_state: serde_json::Value,
    default_outbound: String,
    dns_params: serde_json::Value,
    _allow_server_proxy: bool,
    zone_priority: Vec<String>,
    proxy_lan: bool,
    _kill_switch: bool,
    app_routing_mode: String,
    app_packages: Vec<String>,
) -> Result<String, String> {
    if vless_link.starts_with("ovpn://") {
        return Err("OpenVPN chaining is not implemented on Android yet".into());
    }

    let prepared = app.karin_vpn().prepare().map_err(|e| e.to_string())?;
    if !prepared.prepared {
        return Err("VPN permission was denied".into());
    }

    let token = generate_token();
    if let Ok(mut guard) = state.auth_token.lock() {
        *guard = Some(token.clone());
    }

    let proxy_outbound = if vless_link.starts_with("wg://") {
        build_android_wireguard_outbound(&vless_link)?
    } else {
        let (outbound, _out_addr, _resolved_ips) = build_proxy_outbound(&vless_link).await?;
        outbound
    };
    let dns_config = build_dns_config(&dns_params, &routing_state);
    let dynamic_rules = build_xray_rules(&routing_state, zone_priority);

    let mut all_rules = vec![
        json!({
            "type": "field",
            "inboundTag": ["tun-in"],
            "port": 53,
            "outboundTag": "dns-out"
        }),
        json!({
            "type": "field",
            "inboundTag": ["ping-in"],
            "outboundTag": "proxy"
        }),
    ];

    let mut local_ips = vec!["127.0.0.0/8".to_string()];
    if !proxy_lan {
        local_ips.extend([
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
            "192.168.0.0/16".to_string(),
            "fc00::/7".to_string(),
            "fe80::/10".to_string(),
        ]);
    }
    all_rules.push(json!({
        "type": "field",
        "ip": local_ips,
        "outboundTag": "direct"
    }));

    if let Some(rules) = dynamic_rules.as_array() {
        all_rules.extend(rules.clone());
    }
    all_rules.push(json!({
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": default_outbound
    }));
    let runtime_routing = build_runtime_routing(&routing_state, "IPIfNonMatch", all_rules);

    let android_tun_mtu = if vless_link.starts_with("wg://") {
        1420
    } else {
        1500
    };

    let config = json!({
        "log": { "loglevel": "warning" },
        "dns": dns_config,
        "routing": runtime_routing,
        "inbounds": [
            {
                "tag": "tun-in",
                "protocol": "tun",
                "settings": {
                    "name": "xray0",
                    "mtu": android_tun_mtu
                },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls", "quic"]
                }
            },
            {
                "tag": "ping-in",
                "listen": "127.0.0.1",
                "port": 2082,
                "protocol": "mixed",
                "settings": {
                    "accounts": [{ "user": "karin", "pass": token }]
                }
            }
        ],
        "outbounds": [
            proxy_outbound,
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" },
            { "tag": "dns-out", "protocol": "dns" }
        ]
    });

    let status = app
        .karin_vpn()
        .start(StartRequest {
            config_json: config.to_string(),
            mtu: android_tun_mtu,
            app_routing_mode,
            app_packages,
        })
        .map_err(|e| e.to_string())?;

    if let Some(err) = status.last_error {
        return Err(err);
    }
    Ok("OK".into())
}

#[cfg(target_os = "android")]
#[tauri::command]
fn get_logs(app: tauri::AppHandle) -> Result<String, String> {
    app.karin_vpn()
        .logs()
        .map(|result| {
            if result.content.trim().is_empty() {
                "Ожидание событий VPN/Xray...".to_string()
            } else {
                result.content
            }
        })
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "android")]
#[tauri::command]
fn clear_logs(app: tauri::AppHandle) -> Result<String, String> {
    app.karin_vpn()
        .clear_logs()
        .map(|_| "Очищено".to_string())
        .map_err(|e| e.to_string())
}

#[cfg(any(target_os = "android", test))]
fn redact_diagnostic_logs(content: &str) -> String {
    content
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if [
                "vless://",
                "vmess://",
                "trojan://",
                "ss://",
                "wg://",
                "ovpn://",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
                || [
                    "password",
                    "privatekey",
                    "private_key",
                    "presharedkey",
                    "authorization",
                    "configjson",
                ]
                .iter()
                .any(|needle| lower.contains(needle))
            {
                "[REDACTED SENSITIVE DATA]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(target_os = "android")]
#[tauri::command]
fn export_diagnostics(app: tauri::AppHandle) -> Result<String, String> {
    let status = app.karin_vpn().status().map_err(|e| e.to_string())?;
    let device = app.karin_vpn().device_info().map_err(|e| e.to_string())?;
    let logs = app.karin_vpn().logs().map_err(|e| e.to_string())?.content;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();

    let safe_last_error =
        redact_diagnostic_logs(&status.last_error.unwrap_or_else(|| "none".to_string()));
    let report = format!(
        "KarinCore Android diagnostics\n\
===========================\n\
App version: {}\n\
Generated (Unix): {}\n\
Architecture: {}\n\
Android: {} (SDK {})\n\
Manufacturer: {}\n\
Brand: {}\n\
Model: {}\n\
Device: {}\n\
Xray core: {}\n\
VPN running: {}\n\
VPN starting: {}\n\
Xray running: {}\n\
Reconnecting: {}\n\
Always-on: {}\n\
Lockdown: {}\n\
TUN established: {}\n\
App routing mode: {}\n\
App routing package count: {}\n\
Last error: {}\n\n\
VPN/Xray logs\n\
-------------\n{}\n",
        env!("CARGO_PKG_VERSION"),
        timestamp,
        std::env::consts::ARCH,
        device.android_release,
        device.sdk_int,
        device.manufacturer,
        device.brand,
        device.model,
        device.device,
        status.core_version.unwrap_or_else(|| "unknown".to_string()),
        status.running,
        status.starting,
        status.core_running,
        status.reconnecting,
        status.always_on,
        status.lockdown,
        status.tun_fd.is_some(),
        status.app_routing_mode,
        status.app_package_count,
        safe_last_error,
        redact_diagnostic_logs(&logs)
    );

    let filename = format!(
        "KarinCore-diagnostics-v{}-{}.txt",
        env!("CARGO_PKG_VERSION"),
        timestamp
    );

    app.karin_vpn()
        .save_document(SaveDocumentRequest {
            filename,
            content: report,
            mime_type: "text/plain".to_string(),
        })
        .map(|result| {
            result
                .uri
                .map(|uri| format!("Сохранено: {}", uri))
                .unwrap_or_else(|| "Сохранено".to_string())
        })
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn export_diagnostics() -> Result<String, String> {
    Err("Диагностика в этом формате доступна только в Android-порте".to_string())
}

#[cfg(target_os = "android")]
#[tauri::command]
fn get_installed_apps(app: tauri::AppHandle) -> Result<Vec<InstalledApp>, String> {
    app.karin_vpn()
        .list_apps()
        .map(|result| result.apps)
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn get_installed_apps() -> Result<Vec<InstalledApp>, String> {
    Ok(Vec::new())
}

#[cfg(target_os = "android")]
#[tauri::command]
fn stop_proxy(app: tauri::AppHandle, state: State<'_, ProxyState>) -> Result<String, String> {
    if let Ok(mut guard) = state.auth_token.lock() {
        *guard = None;
    }
    app.karin_vpn().stop().map_err(|e| e.to_string())?;
    Ok("Остановлено".into())
}

#[cfg(target_os = "android")]
#[tauri::command]
async fn export_profile(
    app: tauri::AppHandle,
    filename: String,
    content: String,
) -> Result<String, String> {
    app.karin_vpn()
        .save_document(SaveDocumentRequest {
            filename,
            content,
            mime_type: "application/json".to_string(),
        })
        .map(|result| {
            result
                .uri
                .map(|uri| format!("Сохранено: {}", uri))
                .unwrap_or_else(|| "Сохранено".to_string())
        })
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "android")]
#[tauri::command]
fn open_browser(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let parsed = Url::parse(&url).map_err(|_| "BROWSER_URL_INVALID".to_string())?;
    if parsed.scheme() != "https" || parsed.host_str() != Some("github.com") {
        return Err("BROWSER_URL_FORBIDDEN".into());
    }
    app.opener()
        .open_url(parsed.as_str(), None::<String>)
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "android")]
#[tauri::command]
fn minimize_window(_window: tauri::Window) {}

#[cfg(target_os = "android")]
#[tauri::command]
fn maximize_window(_window: tauri::Window) {}

#[cfg(target_os = "android")]
#[tauri::command]
fn close_window(_window: tauri::Window) {
    // The Activity/WebView lifecycle must not stop the foreground VPN service.
}

#[cfg(target_os = "android")]
#[tauri::command]
fn get_vpn_runtime_status(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let status = app.karin_vpn().status().map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "running": status.running,
        "starting": status.starting,
        "coreRunning": status.core_running,
        "reconnecting": status.reconnecting,
        "alwaysOn": status.always_on,
        "lockdown": status.lockdown,
        "appRoutingMode": status.app_routing_mode,
        "appPackageCount": status.app_package_count,
        "tunFd": status.tun_fd,
        "coreVersion": status.core_version,
        "lastError": status.last_error
    }))
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn get_vpn_runtime_status() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "running": false,
        "starting": false,
        "coreRunning": false,
        "reconnecting": false,
        "alwaysOn": false,
        "lockdown": false,
        "appRoutingMode": "all",
        "appPackageCount": 0,
        "tunFd": null,
        "coreVersion": null,
        "lastError": null
    }))
}

#[cfg(target_os = "android")]
#[tauri::command]
fn open_android_vpn_settings(app: tauri::AppHandle) -> Result<bool, String> {
    app.karin_vpn()
        .open_vpn_settings()
        .map(|result| result.opened)
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn open_android_vpn_settings() -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "android")]
#[tauri::command]
fn get_android_stability_diagnostics(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let diagnostics = app
        .karin_vpn()
        .stability_diagnostics()
        .map_err(|e| e.to_string())?;
    serde_json::to_value(diagnostics).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn get_android_stability_diagnostics() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "vpnPermissionGranted": false,
        "notificationsGranted": false,
        "batteryOptimizationExempt": false,
        "backgroundRestricted": false,
        "dataSaverStatus": "disabled",
        "networkAvailable": false,
        "networkValidated": false,
        "alwaysOn": false,
        "lockdown": false,
        "sdkInt": 0,
        "manufacturer": ""
    }))
}

#[cfg(target_os = "android")]
#[tauri::command]
fn open_android_stability_settings(app: tauri::AppHandle, target: String) -> Result<bool, String> {
    app.karin_vpn()
        .open_stability_settings(tauri_plugin_karin_vpn::OpenStabilitySettingsRequest { target })
        .map(|result| result.opened)
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn open_android_stability_settings(_target: String) -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "android")]
#[tauri::command]
fn request_android_vpn_permission(app: tauri::AppHandle) -> Result<bool, String> {
    app.karin_vpn()
        .prepare()
        .map(|result| result.prepared)
        .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
fn request_android_vpn_permission() -> Result<bool, String> {
    Ok(false)
}

#[tauri::command]
fn get_runtime_info() -> serde_json::Value {
    serde_json::json!({
        "platform": if cfg!(target_os = "android") { "android" } else { "desktop" },
        "version": env!("CARGO_PKG_VERSION"),
        "updateRepo": "detestern/KarinCore"
    })
}

// **********************************
// MAIN APPLICATION ENTRY POINT
// **********************************
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(not(target_os = "android"))]
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let _ = ensure_xray().await;
        let _ = ensure_geo_files().await;
    });

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_karin_vpn::init())
        .manage(ProxyState {
            auth_token: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            start_proxy,
            stop_proxy,
            fetch_subscription,
            get_geosite_list,
            get_logs,
            clear_logs,
            get_vpn_ip,
            get_vpn_ipv4,
            get_vpn_ipv6,
            check_ping,
            get_installed_apps,
            export_diagnostics,
            export_profile,
            minimize_window,
            maximize_window,
            close_window,
            open_browser,
            save_secure_state,
            load_secure_state,
            get_runtime_info,
            get_vpn_runtime_status,
            open_android_vpn_settings,
            get_android_stability_diagnostics,
            open_android_stability_settings,
            request_android_vpn_permission
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|_app_handle, _event| {
        #[cfg(not(target_os = "android"))]
        if let RunEvent::ExitRequested { .. } | RunEvent::Exit = _event {
            let _ = std::process::Command::new("sudo")
                .args(["/usr/bin/systemctl", "stop", "karin-proxy-daemon.service"])
                .output();
            let _ = std::process::Command::new("sudo")
                .args(["-n", "/usr/libexec/karincore-helper", "openvpn-stop"])
                .output();
            let _ = run_privileged_helper("resolver-restore", &[]);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_rules_preserve_priority_and_supported_rule_types() {
        let state = json!({
            "direct": [
                { "type": "geosite", "value": "private" },
                { "type": "ip", "value": "10.0.0.0/8" }
            ],
            "proxy": [
                { "type": "domain", "value": "example.com" },
                { "type": "keyword", "value": "example" }
            ],
            "block": [{ "type": "unsupported", "value": "ignored" }]
        });

        let rules = build_xray_rules(
            &state,
            vec!["proxy".into(), "direct".into(), "block".into()],
        );

        assert_eq!(
            rules,
            json!([
                {
                    "type": "field",
                    "outboundTag": "proxy",
                    "domain": ["example.com", "keyword:example"]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": ["geosite:private"]
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": ["10.0.0.0/8"]
                }
            ])
        );
    }

    #[test]
    fn routing_and_dns_import_map_outbound_tags_to_ui_zones() {
        let outbounds = vec![
            json!({ "tag": "bypass", "protocol": "freedom" }),
            json!({ "tag": "tunnel", "protocol": "vless" }),
            json!({ "tag": "reject", "protocol": "blackhole" }),
        ];
        let routing = json!({
            "rules": [
                { "outboundTag": "bypass", "domain": ["geosite:private"], "ip": ["10.0.0.0/8"] },
                { "outboundTag": "tunnel", "domain": ["keyword:video"] },
                { "outboundTag": "reject", "domain": ["domain:ads.example"] }
            ]
        });
        let dns = json!({
            "servers": [
                { "address": "1.1.1.1", "outboundTag": "bypass" },
                { "address": "https://dns.example/dns-query", "outboundTag": "tunnel" }
            ]
        });

        assert_eq!(
            convert_routing_to_zones(&routing, &outbounds, false),
            Some(json!({
                "direct": [
                    { "type": "geosite", "value": "private" },
                    { "type": "ip", "value": "10.0.0.0/8" }
                ],
                "proxy": [{ "type": "keyword", "value": "video" }],
                "block": [{ "type": "domain", "value": "domain:ads.example" }]
            }))
        );
        assert_eq!(
            convert_dns_to_params(&dns, &outbounds),
            Some(json!({
                "domestic": { "type": "dou", "url": "", "ip": "1.1.1.1" },
                "remote": { "type": "doh", "url": "https://dns.example/dns-query", "ip": "" }
            }))
        );
    }

    #[test]
    fn dns_config_pins_doh_bootstrap_and_routes_direct_domains() {
        let config = build_dns_config(
            &json!({
                "domestic": { "type": "dou", "ip": "1.1.1.1", "url": "" },
                "remote": { "type": "doh", "ip": "203.0.113.53", "url": "https://dns.example/dns-query" }
            }),
            &json!({
                "direct": [
                    { "type": "geosite", "value": "private" },
                    { "type": "keyword", "value": "lan" }
                ]
            }),
        );

        assert_eq!(config["hosts"]["dns.example"], json!("203.0.113.53"));
        assert_eq!(
            config["servers"][0]["domains"],
            json!(["geosite:private", "keyword:lan"])
        );
        assert_eq!(config["servers"][0]["outboundTag"], json!("direct"));
        assert_eq!(config["servers"][1]["outboundTag"], json!("proxy"));
    }

    #[tokio::test]
    async fn proxy_parsers_generate_expected_outbounds_without_network_lookup() {
        let (vless, _, _) = build_proxy_outbound(
            "vless://11111111-1111-1111-1111-111111111111@192.0.2.10:443?security=reality&pbk=public-key&sni=edge.example&sid=abcd&type=tcp&flow=xtls-rprx-vision",
        )
        .await
        .unwrap();
        assert_eq!(vless["protocol"], json!("vless"));
        assert_eq!(
            vless.pointer("/settings/vnext/0/users/0/id"),
            Some(&json!("11111111-1111-1111-1111-111111111111"))
        );
        assert_eq!(
            vless.pointer("/streamSettings/realitySettings/publicKey"),
            Some(&json!("public-key"))
        );
        assert_eq!(
            vless.pointer("/streamSettings/realitySettings/serverName"),
            Some(&json!("edge.example"))
        );

        let vmess_payload = general_purpose::STANDARD.encode(
            json!({
                "add": "192.0.2.20",
                "port": "8443",
                "id": "22222222-2222-2222-2222-222222222222",
                "aid": "0",
                "scy": "auto",
                "net": "ws",
                "host": "ws.example",
                "path": "/socket",
                "tls": "tls",
                "sni": "tls.example"
            })
            .to_string(),
        );
        let (vmess, _, _) = build_proxy_outbound(&format!("vmess://{vmess_payload}"))
            .await
            .unwrap();
        assert_eq!(vmess["protocol"], json!("vmess"));
        assert_eq!(vmess.pointer("/settings/vnext/0/port"), Some(&json!(8443)));
        assert_eq!(
            vmess.pointer("/streamSettings/wsSettings/path"),
            Some(&json!("/socket"))
        );
        assert_eq!(
            vmess.pointer("/streamSettings/tlsSettings/serverName"),
            Some(&json!("tls.example"))
        );

        let (trojan, _, _) = build_proxy_outbound(
            "trojan://test-password@192.0.2.30:443?security=tls&sni=trojan.example",
        )
        .await
        .unwrap();
        assert_eq!(trojan["protocol"], json!("trojan"));
        assert_eq!(
            trojan.pointer("/settings/servers/0/password"),
            Some(&json!("test-password"))
        );
        assert_eq!(
            trojan.pointer("/streamSettings/tlsSettings/allowInsecure"),
            Some(&json!(false))
        );

        let credentials = general_purpose::STANDARD_NO_PAD.encode("aes-256-gcm:test-secret");
        let (shadowsocks, _, _) =
            build_proxy_outbound(&format!("ss://{credentials}@192.0.2.40:8388#test"))
                .await
                .unwrap();
        assert_eq!(shadowsocks["protocol"], json!("shadowsocks"));
        assert_eq!(
            shadowsocks.pointer("/settings/servers/0/method"),
            Some(&json!("aes-256-gcm"))
        );
        assert_eq!(
            shadowsocks.pointer("/settings/servers/0/password"),
            Some(&json!("test-secret"))
        );
    }

    #[test]
    fn subscription_parser_accepts_plain_and_unpadded_base64_lists() {
        let plain = "vless://id@192.0.2.1:443#one\nwg://?payload=dGVzdA#two";
        let parsed = parse_subscription_content(plain).unwrap();
        assert_eq!(parsed.links.len(), 2);
        assert!(parsed.links[0].starts_with("vless://"));
        assert!(parsed.links[1].starts_with("wg://"));

        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(
            "trojan://secret@192.0.2.2:443#three\nss://YWVzLTEyOC1nY206c2VjcmV0QDE5Mi4wLjIuMzo4Mzg4#four",
        );
        let parsed = parse_subscription_content(&encoded).unwrap();
        assert_eq!(parsed.links.len(), 2);
        assert!(parsed.links[0].starts_with("trojan://"));
        assert!(parsed.links[1].starts_with("ss://"));
    }

    #[test]
    fn subscription_parser_applies_v2raytun_routing_headers() {
        let routing = json!({
            "domainStrategy": "AsIs",
            "domainMatcher": "hybrid",
            "name": "Direct Russia",
            "rules": [
                {
                    "type": "field",
                    "domain": ["regexp:.*\\.ru$", "geosite:category-ru"],
                    "ip": ["geoip:ru"],
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "domain": ["geosite:category-ads-all"],
                    "outboundTag": "block"
                }
            ]
        });
        let header = general_purpose::STANDARD.encode(routing.to_string());
        let body = "vless://id@192.0.2.1:443?security=tls#one";

        let parsed = parse_subscription_content_with_routing(body, Some(&header)).unwrap();
        assert!(parsed.routing_override);
        let imported = parsed.imported_routing.unwrap();
        assert_eq!(
            imported["direct"],
            json!([
                { "type": "domain", "value": "regexp:.*\\.ru$" },
                { "type": "geosite", "value": "category-ru" },
                { "type": "ip", "value": "geoip:ru" }
            ])
        );
        assert_eq!(
            imported["block"],
            json!([{ "type": "geosite", "value": "category-ads-all" }])
        );
        assert_eq!(imported["_domainStrategy"], "AsIs");
        assert_eq!(imported["_domainMatcher"], "hybrid");

        let xray_rules = build_xray_rules(
            &imported,
            vec!["direct".into(), "proxy".into(), "block".into()],
        );
        assert_eq!(
            xray_rules[0],
            json!({
                "type": "field",
                "outboundTag": "direct",
                "domain": ["regexp:.*\\.ru$", "geosite:category-ru"]
            })
        );
        assert_eq!(
            xray_rules[1],
            json!({
                "type": "field",
                "outboundTag": "direct",
                "ip": ["geoip:ru"]
            })
        );
        assert_eq!(xray_rules[2]["outboundTag"], "block");

        let runtime = build_runtime_routing(
            &imported,
            "IPIfNonMatch",
            xray_rules.as_array().unwrap().clone(),
        );
        assert_eq!(runtime["domainStrategy"], "AsIs");
        assert_eq!(runtime["domainMatcher"], "hybrid");
    }

    #[test]
    fn subscription_parser_applies_v2raytun_top_level_routing_array() {
        let routing = json!([
            {
                "ip": ["geoip:private"],
                "outboundTag": "direct"
            },
            {
                "domain": ["geosite:private"],
                "outboundTag": "direct"
            },
            {
                "domain": [
                    "geosite:category-ru",
                    "regexp:.*\\.ru$",
                    "regexp:.*\\.su$",
                    "regexp:.*\\.xn--p1ai$"
                ],
                "outboundTag": "direct"
            },
            {
                "ip": ["geoip:ru"],
                "outboundTag": "direct"
            },
            {
                "outboundTag": "proxy",
                "port": "0-65535"
            }
        ]);
        let header = general_purpose::STANDARD.encode(routing.to_string());
        let body = "vless://id@192.0.2.1:443?security=tls#one";

        let parsed = parse_subscription_content_with_routing(body, Some(&header)).unwrap();
        assert!(parsed.routing_override);
        let imported = parsed.imported_routing.unwrap();
        assert_eq!(imported["_providerRules"].as_array().unwrap().len(), 5);
        assert_eq!(
            imported["_providerRules"][4],
            json!({
                "type": "field",
                "outboundTag": "proxy",
                "port": "0-65535"
            })
        );

        let xray_rules = build_xray_rules(
            &imported,
            vec!["direct".into(), "proxy".into(), "block".into()],
        );
        let expected = routing
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| {
                let mut rule = rule.clone();
                rule.as_object_mut()
                    .unwrap()
                    .insert("type".into(), json!("field"));
                rule
            })
            .collect::<Vec<_>>();
        assert_eq!(xray_rules, Value::Array(expected));
    }

    #[test]
    fn subscription_parser_reads_v2raytun_routing_from_decoded_body() {
        let routing = json!({
            "rules": [{
                "type": "field",
                "domain": ["domain:example.org"],
                "outboundTag": "direct"
            }]
        });
        let header = general_purpose::URL_SAFE_NO_PAD.encode(routing.to_string());
        let decoded = format!("routing: \"{header}\"\nvless://id@192.0.2.1:443?security=tls#one");
        let body = general_purpose::STANDARD.encode(decoded);

        let parsed = parse_subscription_content(&body).unwrap();
        assert!(parsed.routing_override);
        assert_eq!(
            parsed.imported_routing.unwrap()["direct"],
            json!([{ "type": "domain", "value": "domain:example.org" }])
        );
    }

    #[test]
    fn subscription_json_imports_vless_routing_and_dns() {
        let input = json!({
            "remarks": "Imported profile",
            "outbounds": [
                {
                    "tag": "proxy-out",
                    "protocol": "vless",
                    "settings": { "vnext": [{
                        "address": "192.0.2.50",
                        "port": 443,
                        "users": [{ "id": "33333333-3333-3333-3333-333333333333", "flow": "" }]
                    }] },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "publicKey": "public-key",
                            "serverName": "import.example",
                            "shortId": "1234",
                            "fingerprint": "chrome"
                        }
                    }
                },
                { "tag": "direct-out", "protocol": "freedom" }
            ],
            "routing": { "rules": [{
                "outboundTag": "direct-out",
                "domain": ["geosite:private"]
            }] },
            "dns": { "servers": [{
                "address": "9.9.9.9",
                "outboundTag": "direct-out"
            }] }
        })
        .to_string();

        let parsed = parse_subscription_content(&input).unwrap();
        assert_eq!(parsed.links.len(), 1);
        assert!(parsed.links[0].contains("#Imported%20profile"));
        assert_eq!(
            parsed.imported_routing.unwrap()["direct"][0],
            json!({
                "type": "geosite",
                "value": "private"
            })
        );
        assert_eq!(
            parsed.imported_dns.unwrap()["domestic"]["ip"],
            json!("9.9.9.9")
        );
    }

    #[test]
    fn wireguard_sanitization_removes_commands_case_insensitively() {
        let sanitized = sanitize_wg_config(
            "[Interface]\nPrivateKey = secret\nPreUp = touch /tmp/bad\nPOSTDOWN=shutdown\n[Peer]\nPublicKey = public",
        );

        assert!(sanitized.contains("PrivateKey = secret"));
        assert!(sanitized.contains("PublicKey = public"));
        assert!(!sanitized.to_ascii_lowercase().contains("preup"));
        assert!(!sanitized.to_ascii_lowercase().contains("postdown"));
    }

    #[test]
    fn wireguard_parser_generates_userspace_outbound_and_defaults() {
        let config = "[Interface]\nPrivateKey = private-key\nAddress = 10.10.0.2/32, fd00::2/128\nMTU = 99999\nReserved = 1, 2, 3\nPostUp = unsafe-command\n\n[Peer]\nPublicKey = public-key\nPresharedKey = preshared-key\nEndpoint = 192.0.2.60:51820\nPersistentKeepalive = 25";
        let payload = general_purpose::URL_SAFE_NO_PAD.encode(config);
        let outbound =
            build_android_wireguard_outbound(&format!("wg://?payload={payload}")).unwrap();

        assert_eq!(outbound["protocol"], json!("wireguard"));
        assert_eq!(
            outbound.pointer("/settings/noKernelTun"),
            Some(&json!(true))
        );
        assert_eq!(outbound.pointer("/settings/mtu"), Some(&json!(9000)));
        assert_eq!(
            outbound.pointer("/settings/address"),
            Some(&json!(["10.10.0.2", "fd00::2"]))
        );
        assert_eq!(
            outbound.pointer("/settings/remoteDNS"),
            Some(&json!(["1.1.1.1", "1.0.0.1"]))
        );
        assert_eq!(
            outbound.pointer("/settings/reserved"),
            Some(&json!([1, 2, 3]))
        );
        assert_eq!(
            outbound.pointer("/settings/peers/0/allowedIPs"),
            Some(&json!(["0.0.0.0/0", "::/0"]))
        );
    }

    #[test]
    fn wireguard_parser_rejects_missing_required_fields() {
        let missing_private_key = "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = public\nEndpoint = 192.0.2.1:51820";
        let payload = general_purpose::STANDARD.encode(missing_private_key);
        let error =
            build_android_wireguard_outbound(&format!("wg://?payload={payload}")).unwrap_err();
        assert!(error.contains("Interface.PrivateKey"));
    }

    #[test]
    fn diagnostic_log_redaction_covers_every_supported_secret_uri() {
        let logs = [
            "connecting vless://uuid@host",
            "connecting vmess://payload",
            "connecting trojan://password@host",
            "connecting ss://secret@host",
            "connecting wg://?payload=private-key",
            "ordinary status line",
        ]
        .join("\n");

        let redacted = redact_diagnostic_logs(&logs);
        assert_eq!(redacted.matches("[REDACTED SENSITIVE DATA]").count(), 5);
        assert!(redacted.ends_with("ordinary status line"));
        assert!(!redacted.contains("private-key"));
        assert!(!redacted.contains("password"));
    }

    #[test]
    fn subscription_url_policy_rejects_cleartext_credentials_and_private_hosts() {
        assert!(validate_subscription_url("https://example.com/sub").is_ok());
        assert!(validate_subscription_url("http://example.com/sub").is_err());
        assert!(validate_subscription_url("https://user:pass@example.com/sub").is_err());
        assert!(validate_subscription_url("https://127.0.0.1/sub").is_err());
        assert!(validate_subscription_url("https://192.168.1.1/sub").is_err());
        assert!(validate_subscription_url("https://100.64.0.1/sub").is_err());
        assert!(validate_subscription_url("https://[fc00::1]/sub").is_err());
        assert!(validate_subscription_url("https://[fe80::1]/sub").is_err());
        assert!(validate_subscription_url("https://service.local/sub").is_err());
    }

    #[test]
    fn subscription_json_percent_encodes_untrusted_remarks() {
        let json = r#"{"remarks":"<img src=x onerror=alert(1)>","outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"uuid"}]}]}}]}"#;
        let result = parse_subscription_content(json).unwrap();
        assert_eq!(result.links.len(), 1);
        assert!(!result.links[0].contains('<'));
        assert!(result.links[0].contains("%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"));
    }

    #[test]
    fn vpn_ip_probe_accepts_only_ip_addresses() {
        assert_eq!(
            validate_probe_ip("203.0.113.10".to_string()).unwrap(),
            "203.0.113.10"
        );
        assert_eq!(
            validate_probe_ip("2001:db8::1".to_string()).unwrap(),
            "2001:db8::1"
        );
        assert!(validate_probe_ip("<html>proxy error</html>".to_string()).is_err());
    }
}
