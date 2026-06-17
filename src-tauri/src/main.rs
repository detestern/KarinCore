#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// **********************************
// IMPORTS
// **********************************
use tauri::{State, RunEvent};
use url::Url;
use std::path::Path;
use tokio::fs;
use base64::{Engine as _, engine::general_purpose};
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// **********************************
// STATE & AUTHENTICATION
// **********************************
struct ProxyState {
    auth_token: Mutex<Option<String>>,
}

fn generate_token() -> String {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("karin_token_{:x}", time)
}

// **********************************
// CORE HELPER FUNCTIONS
// **********************************
fn get_log_paths() -> (String, String) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let log_dir = format!("{}/.local/share/karin-proxy", home);
    
    let _ = std::fs::create_dir_all(&log_dir);
    
    let err_log = format!("{}/error.log", log_dir);
    let acc_log = format!("{}/access.log", log_dir);
    
    (err_log, acc_log)
}

fn build_xray_rules(state: Value) -> Value {
    let mut rules = Vec::new();
    
    if let Some(state_object) = state.as_object() {
        for (tag, rules_list) in state_object {
            if let Some(rules_array) = rules_list.as_array() {
                let mut domains = Vec::new();
                let mut ips = Vec::new();
                
                for rule in rules_array {
                    let r_type = rule.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let r_val = rule.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    
                    match r_type {
                        "geosite" => domains.push(format!("geosite:{}", r_val)),
                        "domain" => domains.push(r_val.to_string()),
                        "ip" => ips.push(r_val.to_string()),
                        _ => {}
                    }
                }
                
                if !domains.is_empty() || !ips.is_empty() {
                    rules.push(json!({ 
                        "type": "field", 
                        "outboundTag": tag, 
                        "domain": domains, 
                        "ip": ips 
                    }));
                }
            }
        }
    }
    json!(rules)
}

async fn ensure_geo_files() -> Result<(), String> {
    if !Path::new("/etc/karin-proxy/geo").exists() {
        std::process::Command::new("sudo").args(["mkdir", "-p", "/etc/karin-proxy/geo"]).output().ok();
    }

    let files = vec![
        ("geosite.dat", "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"),
        ("geoip.dat", "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"),
    ];
    
    for (filename, url) in files {
        let final_path = format!("/etc/karin-proxy/geo/{}", filename);
        if !Path::new(&final_path).exists() {
            println!("Скачивание {}...", filename);
            let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
            let content = response.bytes().await.map_err(|e| e.to_string())?;
            
            let tmp_path = format!("/tmp/{}", filename);
            fs::write(&tmp_path, &content).await.map_err(|e| e.to_string())?;
            
            std::process::Command::new("sudo").args(["cp", &tmp_path, &final_path]).output().ok();
            std::process::Command::new("rm").args(["-f", &tmp_path]).output().ok();
        }
    }
    
    Ok(())
}

fn teardown_connections() {
    std::process::Command::new("sudo").args(["/usr/bin/systemctl", "stop", "karin-proxy-daemon.service"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/pkill", "-f", "/etc/karin-proxy/openvpn.ovpn"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/wg-quick", "down", "/etc/karin-proxy/wg0.conf"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "wg0", "-j", "MASQUERADE"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/ip", "rule", "del", "fwmark", "111", "lookup", "111"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "tun-ovpn", "-j", "MASQUERADE"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/cp", "/etc/karin-proxy/resolv.conf.bak", "/etc/resolv.conf"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/rm", "-f", "/etc/karin-proxy/resolv.conf.bak"]).output().ok();
}

// **********************************
// TAURI COMMANDS: PROXY & NETWORK MANAGEMENT
// **********************************
#[tauri::command]
async fn fetch_subscription(url: String) -> Result<Vec<String>, String> {
    let client = reqwest::Client::builder()
        .user_agent("v2rayNG/1.8.5")
        .build()
        .map_err(|e| format!("Ошибка HTTP клиента: {}", e))?;
        
    let mut current_url = url.clone();
    let mut text = String::new();
    let mut attempts = 0;

    while attempts < 2 {
        let response = client.get(&current_url).send().await.map_err(|e| format!("Ошибка сети: {}", e))?;
        let status = response.status();
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
    
    let parse_json = |json_str: &str, out_links: &mut Vec<String>| {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
            let arr = if let Some(a) = json.as_array() {
                a.clone()
            } else {
                vec![json]
            };

            for item in arr {
                let remarks = item.get("remarks").and_then(|v| v.as_str()).unwrap_or("Proxy");
                if let Some(outbounds) = item.get("outbounds").and_then(|v| v.as_array()) {
                    for out in outbounds {
                        if out.get("protocol").and_then(|v| v.as_str()) == Some("vless") {
                            let address = out.pointer("/settings/vnext/0/address").and_then(|v| v.as_str()).unwrap_or("");
                            let port = out.pointer("/settings/vnext/0/port").and_then(|v| v.as_u64()).unwrap_or(443);
                            let id = out.pointer("/settings/vnext/0/users/0/id").and_then(|v| v.as_str()).unwrap_or("");
                            let flow = out.pointer("/settings/vnext/0/users/0/flow").and_then(|v| v.as_str()).unwrap_or("");
                            
                            let stream = out.get("streamSettings");
                            let network = stream.and_then(|v| v.pointer("/network")).and_then(|v| v.as_str()).unwrap_or("tcp");
                            let security = stream.and_then(|v| v.pointer("/security")).and_then(|v| v.as_str()).unwrap_or("none");
                            let pbk = stream.and_then(|v| v.pointer("/realitySettings/publicKey")).and_then(|v| v.as_str()).unwrap_or("");
                            let sni = stream.and_then(|v| v.pointer("/realitySettings/serverName")).and_then(|v| v.as_str()).unwrap_or("");
                            let sid = stream.and_then(|v| v.pointer("/realitySettings/shortId")).and_then(|v| v.as_str()).unwrap_or("");
                            let fp = stream.and_then(|v| v.pointer("/realitySettings/fingerprint")).and_then(|v| v.as_str()).unwrap_or("firefox");

                            let safe_remarks = remarks.replace(' ', "%20");
                            let link = format!("vless://{}@{}:{}?type={}&security={}&pbk={}&sni={}&sid={}&fp={}&flow={}#{}",
                                id, address, port, network, security, pbk, sni, sid, fp, flow, safe_remarks
                            );
                            out_links.push(link);
                            break;
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

    parse_json(&text, &mut links);
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
            parse_json(&decoded_str, &mut links);
            if links.is_empty() { parse_plain(&decoded_str, &mut links); }
        }
    }

    if links.is_empty() { 
        return Err("Не удалось найти профили.\nВозможно формат не поддерживается.".into()); 
    }
    
    Ok(links)
}

async fn start_openvpn_proxy(
    _state: State<'_, ProxyState>,
    ovpn_link: String,
    routing_state: serde_json::Value,
    default_outbound: String,
    _dns_params: serde_json::Value,
    allow_server_proxy: bool,
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

    let decoded_bytes = general_purpose::STANDARD.decode(&b64_payload)
        .map_err(|e| format!("Ошибка декодирования Base64: {}", e))?;
    
    let mut ovpn_config = String::from_utf8(decoded_bytes)
        .map_err(|e| format!("Ошибка UTF-8 при сборке конфигурации: {}", e))?;

    // Извлекаем IP адреса серверов OVPN для удаления маршрутов
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

    ovpn_config.push_str("\npull-filter ignore \"redirect-gateway\"\npull-filter ignore \"dhcp-option DNS\"\npull-filter ignore \"tun-mtu\"\ntun-mtu 1360\nmssfix 1320\ndev tun-ovpn\nmark 255\n");

    let config_path = "/etc/karin-proxy/openvpn.ovpn";
    std::fs::write(config_path, ovpn_config).map_err(|e| format!("Ошибка записи файла на диск: {}", e))?;

    let vpn_dns_content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
    let _ = std::fs::write("/etc/karin-proxy/resolv.conf.vpn", vpn_dns_content);

    if !std::path::Path::new("/etc/karin-proxy/resolv.conf.bak").exists() {
        let _ = std::process::Command::new("sudo")
            .args(["cp", "/etc/resolv.conf", "/etc/karin-proxy/resolv.conf.bak"])
            .output();
    }
    
    let _ = std::process::Command::new("sudo")
        .args(["cp", "/etc/karin-proxy/resolv.conf.vpn", "/etc/resolv.conf"])
        .output();

    std::process::Command::new("sudo").args(["systemctl", "stop", "karin-proxy-daemon.service"]).output().ok();
    std::process::Command::new("sudo").args(["pkill", "-f", "/etc/karin-proxy/openvpn.ovpn"]).output().ok();

    let mut child = tokio::process::Command::new("sudo")
        .args(["/usr/bin/openvpn", "--config", config_path])
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
            if let Ok(mut file) = tokio::fs::OpenOptions::new().create(true).append(true).open(&err_log_stdout).await {
                use tokio::io::AsyncWriteExt;
                let _ = file.write_all(format!("{}\n", line).as_bytes()).await;
            }
        }
    });

    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut reader = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if let Ok(mut file) = tokio::fs::OpenOptions::new().create(true).append(true).open(&err_log_stderr).await {
                use tokio::io::AsyncWriteExt;
                let _ = file.write_all(format!("{}\n", line).as_bytes()).await;
            }
        }
    });

    let mut attempts = 0;
    while attempts < 20 {
        if std::path::Path::new("/sys/class/net/tun-ovpn").exists() {
            std::process::Command::new("sudo").args(["/usr/bin/ip", "rule", "del", "fwmark", "111", "lookup", "111"]).output().ok();
            std::process::Command::new("sudo").args(["/usr/bin/ip", "route", "add", "default", "dev", "tun-ovpn", "table", "111"]).output().ok();
            std::process::Command::new("sudo").args(["/usr/bin/ip", "rule", "add", "fwmark", "111", "lookup", "111"]).output().ok();
            std::process::Command::new("sudo").args(["/usr/bin/sysctl", "-w", "net.ipv4.conf.tun-ovpn.rp_filter=0"]).output().ok();
            std::process::Command::new("sudo").args(["/usr/bin/sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"]).output().ok();
            std::process::Command::new("sudo").args(["/usr/bin/iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "tun-ovpn", "-j", "MASQUERADE"]).output().ok();
            std::process::Command::new("sudo").args(["/usr/bin/iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "tun-ovpn", "-j", "MASQUERADE"]).output().ok();
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

    let dynamic_rules = build_xray_rules(routing_state);

    let mut all_rules = vec![];
    all_rules.push(json!({ "type": "field", "ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"], "outboundTag": "direct" }));

    if let Some(rules_array) = dynamic_rules.as_array() { 
        all_rules.extend(rules_array.clone()); 
    }
    all_rules.push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": default_outbound }));

    let (err_log, acc_log) = get_log_paths();

    let config = serde_json::json!({
        "log": { "loglevel": "debug", "access": acc_log, "error": err_log },
        "routing": { "domainStrategy": "AsIs", "rules": all_rules },
        "inbounds": [
            { 
                "port": 2080, 
                "listen": "127.0.0.1", 
                "protocol": "mixed", 
                "settings": { "accounts": [ { "user": "karin", "pass": "openvpn_mode" } ] } 
            },
            { 
                "tag": "tun-in", 
                "port": 2081, 
                "listen": "127.0.0.1", 
                "protocol": "tun", 
                "settings": { "name": "tun0", "mtu": 1500, "gateway": ["172.19.0.1/30"], "autoRoute": true }, 
                "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] } 
            }
        ],
        "outbounds": [
            { "tag": "proxy", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 111, "interface": "tun-ovpn" } } },
            { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 255 } } },
            { "tag": "block", "protocol": "blackhole" }
        ]
    });

    std::fs::write("/etc/karin-proxy/config.json", config.to_string()).map_err(|e| e.to_string())?;

    let output = std::process::Command::new("sudo").args(["systemctl", "restart", "karin-proxy-daemon.service"]).output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        teardown_connections();
        return Err("Ядро упало при попытке инициализации Матрёшки".into());
    }

    if let Ok(mut guard) = _state.auth_token.lock() { *guard = Some("openvpn_mode".to_string()); }

    if allow_server_proxy && !resolved_ips_for_route_del.is_empty() {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            for ip in resolved_ips_for_route_del {
                let _ = std::process::Command::new("sudo").args(["-n", "/usr/bin/ip", "rule", "del", "to", &ip, "lookup", "main"]).output();
                let ip_32 = format!("{}/32", ip);
                let _ = std::process::Command::new("sudo").args(["-n", "/usr/bin/ip", "rule", "del", "to", &ip_32, "lookup", "main"]).output();
                let _ = std::process::Command::new("sudo").args(["-n", "/usr/bin/ip", "route", "del", &ip]).output();
                let _ = std::process::Command::new("sudo").args(["-n", "/usr/bin/ip", "route", "del", &ip_32]).output();
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
) -> Result<String, String> {
    let parsed_url = Url::parse(&wg_link).map_err(|e| e.to_string())?;
    
    let mut b64_payload = String::new();
    for (k, v) in parsed_url.query_pairs() {
        if k == "payload" { b64_payload = v.to_string(); }
    }

    if b64_payload.is_empty() { return Err("Ошибка: В полученной ссылке отсутствует payload конфигурации".into()); }

    let decoded_bytes = general_purpose::STANDARD.decode(&b64_payload).map_err(|e| format!("Ошибка Base64: {}", e))?;
    let original_conf = String::from_utf8(decoded_bytes).map_err(|e| format!("Ошибка UTF-8: {}", e))?;

    let mut resolved_ips_for_route_del: Vec<String> = vec![];
    let mut modified_conf = String::new();
    
    for line in original_conf.lines() {
        let trimmed = line.trim();
        if trimmed.to_lowercase().starts_with("dns") { continue; }
        
        // Извлекаем IP адреса серверов WG для удаления маршрутов
        if trimmed.to_lowercase().starts_with("endpoint") {
            let parts: Vec<&str> = trimmed.split('=').collect();
            if parts.len() >= 2 {
                let endpoint = parts[1].trim();
                let host = endpoint.rsplit_once(':').map(|(h, _)| h).unwrap_or(endpoint);
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    resolved_ips_for_route_del.push(ip.to_string());
                } else if let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:80", host)).await {
                    while let Some(addr) = addrs.next() {
                        resolved_ips_for_route_del.push(addr.ip().to_string());
                    }
                }
            }
        }
        
        modified_conf.push_str(line);
        modified_conf.push('\n');
        
        if trimmed.to_lowercase() == "[interface]" {
            modified_conf.push_str("Table = off\n");
            modified_conf.push_str("FwMark = 255\n"); 
        }
    }

    let config_path = "/etc/karin-proxy/wg0.conf";
    std::fs::write(config_path, modified_conf).map_err(|e| format!("Ошибка записи файла: {}", e))?;

    let vpn_dns_content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
    let _ = std::fs::write("/etc/karin-proxy/resolv.conf.vpn", vpn_dns_content);
    if !std::path::Path::new("/etc/karin-proxy/resolv.conf.bak").exists() {
        let _ = std::process::Command::new("sudo").args(["cp", "/etc/resolv.conf", "/etc/karin-proxy/resolv.conf.bak"]).output();
    }
    let _ = std::process::Command::new("sudo").args(["cp", "/etc/karin-proxy/resolv.conf.vpn", "/etc/resolv.conf"]).output();

    std::process::Command::new("sudo").args(["systemctl", "stop", "karin-proxy-daemon.service"]).output().ok();
    std::process::Command::new("sudo").args(["wg-quick", "down", config_path]).output().ok();

    let output = std::process::Command::new("sudo").args(["/usr/bin/wg-quick", "up", config_path]).output().map_err(|e| format!("Не удалось запустить wg-quick: {}", e))?;

    let (err_log, _) = get_log_paths();

    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&err_log) {
        use std::io::Write;
        let _ = writeln!(file, "[WireGuard] Инициализация интерфейса wg0...");
        if !output.stdout.is_empty() { let _ = writeln!(file, "{}", String::from_utf8_lossy(&output.stdout)); }
        if !output.stderr.is_empty() { let _ = writeln!(file, "{}", String::from_utf8_lossy(&output.stderr)); }
    }

    if !output.status.success() {
        teardown_connections();
        return Err(format!("Ошибка WireGuard:\n{}", String::from_utf8_lossy(&output.stderr)));
    }

    std::process::Command::new("sudo").args(["/usr/bin/ip", "rule", "del", "fwmark", "111", "lookup", "111"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/ip", "route", "add", "default", "dev", "wg0", "table", "111"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/ip", "rule", "add", "fwmark", "111", "lookup", "111"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/sysctl", "-w", "net.ipv4.conf.wg0.rp_filter=0"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "wg0", "-j", "MASQUERADE"]).output().ok();
    std::process::Command::new("sudo").args(["/usr/bin/iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wg0", "-j", "MASQUERADE"]).output().ok();

    let log_path_clone = err_log.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3));
        loop {
            interval.tick().await;
            if !std::path::Path::new("/sys/class/net/wg0").exists() { break; }
            let wg_status = std::process::Command::new("sudo").args(["/usr/bin/wg", "show", "wg0"]).output();
            if let Ok(out) = wg_status {
                if out.status.success() {
                    let status_str = String::from_utf8_lossy(&out.stdout);
                    let mut log_lines = Vec::new();
                    for line in status_str.lines() {
                        if line.contains("latest handshake:") || line.contains("transfer:") || line.contains("endpoint:") {
                            log_lines.push(line.trim().to_string());
                        }
                    }
                    if !log_lines.is_empty() {
                        if let Ok(mut file) = tokio::fs::OpenOptions::new().create(true).append(true).open(&log_path_clone).await {
                            use tokio::io::AsyncWriteExt;
                            let _ = file.write_all(format!("[WireGuard Status] {}\n", log_lines.join(" | ")).as_bytes()).await;
                        }
                    }
                }
            }
        }
    });

    let dynamic_rules = build_xray_rules(routing_state);

    let mut all_rules = vec![];
    all_rules.push(json!({ "type": "field", "ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"], "outboundTag": "direct" }));

    if let Some(rules_array) = dynamic_rules.as_array() { 
        all_rules.extend(rules_array.clone()); 
    }
    all_rules.push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": default_outbound }));

    let (err_log, acc_log) = get_log_paths();

    let config = serde_json::json!({
        "log": { "loglevel": "debug", "access": acc_log, "error": err_log },
        "routing": { "domainStrategy": "AsIs", "rules": all_rules },
        "inbounds": [
            { 
                "port": 2080, 
                "listen": "127.0.0.1", 
                "protocol": "mixed", 
                "settings": { "accounts": [ { "user": "karin", "pass": "wireguard_mode" } ] } 
            },
            { 
                "tag": "tun-in", 
                "port": 2081, 
                "listen": "127.0.0.1", 
                "protocol": "tun", 
                "settings": { "name": "tun0", "mtu": 1420, "gateway": ["172.19.0.1/30"], "autoRoute": true }, 
                "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] } 
            }
        ],
        "outbounds": [
            { "tag": "proxy", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 111, "interface": "wg0" } } },
            { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 255 } } },
            { "tag": "block", "protocol": "blackhole" }
        ]
    });

    std::fs::write("/etc/karin-proxy/config.json", config.to_string()).map_err(|e| e.to_string())?;

    let output = std::process::Command::new("sudo").args(["systemctl", "restart", "karin-proxy-daemon.service"]).output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        teardown_connections();
        return Err("Ядро упало при попытке инициализации WireGuard".into());
    }

    if let Ok(mut guard) = _state.auth_token.lock() { *guard = Some("wireguard_mode".to_string()); }

    if allow_server_proxy && !resolved_ips_for_route_del.is_empty() {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            for ip in resolved_ips_for_route_del {
                let _ = std::process::Command::new("sudo").args(["-n", "/usr/bin/ip", "rule", "del", "to", &ip, "lookup", "main"]).output();
                let ip_32 = format!("{}/32", ip);
                let _ = std::process::Command::new("sudo").args(["-n", "/usr/bin/ip", "rule", "del", "to", &ip_32, "lookup", "main"]).output();
                let _ = std::process::Command::new("sudo").args(["-n", "/usr/bin/ip", "route", "del", &ip]).output();
                let _ = std::process::Command::new("sudo").args(["-n", "/usr/bin/ip", "route", "del", &ip_32]).output();
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
    _dns_params: serde_json::Value,
    allow_server_proxy: bool
) -> Result<String, String> {
    teardown_connections();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    if vless_link.starts_with("ovpn://") {
        return start_openvpn_proxy(_state, vless_link, routing_state, default_outbound, _dns_params, allow_server_proxy).await;
    }

    if vless_link.starts_with("wg://") {
        return start_wireguard_proxy(_state, vless_link, routing_state, default_outbound, _dns_params, allow_server_proxy).await;
    }

    let token = generate_token();
    if let Ok(mut guard) = _state.auth_token.lock() { *guard = Some(token.clone()); }

    let vpn_dns_content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
    let _ = std::fs::write("/etc/karin-proxy/resolv.conf.vpn", vpn_dns_content);

    if !std::path::Path::new("/etc/karin-proxy/resolv.conf.bak").exists() {
        let _ = std::process::Command::new("sudo").args(["cp", "/etc/resolv.conf", "/etc/karin-proxy/resolv.conf.bak"]).output();
    }
    
    let _ = std::process::Command::new("sudo").args(["cp", "/etc/karin-proxy/resolv.conf.vpn", "/etc/resolv.conf"]).output();

    let parsed_url = Url::parse(&vless_link).map_err(|e| e.to_string())?;
    let server = parsed_url.host_str().unwrap_or("").to_string();
    let port = parsed_url.port().unwrap_or(443);
    let uuid = parsed_url.username().to_string();
    
    // Получаем реальные IP адреса
    let mut resolved_ips: Vec<String> = vec![];
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        resolved_ips.push(ip.to_string());
    } else if let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:{}", server, port)).await {
        while let Some(addr) = addrs.next() {
            resolved_ips.push(addr.ip().to_string());
        }
    }
    if resolved_ips.is_empty() { resolved_ips.push(server.clone()); }
    
    let out_addr = resolved_ips.first().unwrap_or(&server).clone();

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

    let dynamic_rules = build_xray_rules(routing_state);

    let mut all_rules = vec![];

    // Защита локальных сетей
    all_rules.push(json!({ "type": "field", "ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"], "outboundTag": "direct" }));

    // Пользовательские правила
    if let Some(rules_array) = dynamic_rules.as_array() { 
        all_rules.extend(rules_array.clone()); 
    }

    // Дефолт
    all_rules.push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": default_outbound }));
        
    let final_network = if transport_type == "xhttp" || transport_type == "httpupgrade" { "xhttp" } else { "tcp" };

    let mut stream_settings = serde_json::Map::new();
    stream_settings.insert("network".to_string(), json!(final_network));
    stream_settings.insert("security".to_string(), json!(security));
    stream_settings.insert("sockopt".to_string(), json!({ "mark": 255 }));
    
    if security == "reality" {
        stream_settings.insert("realitySettings".to_string(), json!({ 
            "publicKey": pbk, "shortId": sid, "serverName": sni, "fingerprint": fp, "spiderX": spx 
        }));
    } else if security == "tls" {
        stream_settings.insert("tlsSettings".to_string(), json!({ 
            "serverName": sni, "allowInsecure": false, "fingerprint": fp 
        }));
    }
    
    if final_network == "xhttp" {
        stream_settings.insert("xhttpSettings".to_string(), json!({ 
            "path": path, "host": host, "mode": mode 
        }));
    }

    let mut user_obj = serde_json::Map::new();
    user_obj.insert("id".to_string(), json!(uuid));
    user_obj.insert("encryption".to_string(), json!("none"));
    
    if !flow.is_empty() && (security == "reality" || security == "tls") {
        user_obj.insert("flow".to_string(), json!(flow));
    }

    let (err_log, acc_log) = get_log_paths();

    let config = serde_json::json!({
        "log": { 
            "loglevel": "debug",
            "access": acc_log,
            "error": err_log
        },
        "routing": { 
            "domainStrategy": "AsIs", 
            "rules": all_rules 
        },
        "inbounds": [
            { 
                "port": 2080, 
                "listen": "127.0.0.1", 
                "protocol": "mixed", 
                "settings": { 
                    "accounts": [ { "user": "karin", "pass": token } ] 
                } 
            },
            { 
                "tag": "tun-in", 
                "port": 2081, 
                "listen": "127.0.0.1", 
                "protocol": "tun", 
                "settings": { "name": "tun0", "mtu": 1500, "gateway": ["172.19.0.1/30"], "autoRoute": true }, 
                "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] } 
            }
        ],
        "outbounds": [
            { 
                "tag": "proxy", 
                "protocol": "vless", 
                "settings": { "vnext": [{ "address": out_addr, "port": port, "users": [Value::Object(user_obj)] }] }, 
                "streamSettings": Value::Object(stream_settings) 
            },
            { 
                "tag": "direct", 
                "protocol": "freedom", 
                "streamSettings": { "sockopt": { "mark": 255 } } 
            },
            { 
                "tag": "block", 
                "protocol": "blackhole" 
            }
        ]
    });

    std::fs::write("/etc/karin-proxy/config.json", config.to_string()).map_err(|e| e.to_string())?;

    let rotate_if_needed = |path: &str| {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > 5 * 1024 * 1024 {
                let _ = std::fs::write(path, ""); 
            }
        }
    };

    rotate_if_needed(&err_log);
    rotate_if_needed(&acc_log);

    let _ = std::fs::OpenOptions::new().create(true).append(true).open(&err_log);
    let _ = std::fs::OpenOptions::new().create(true).append(true).open(&acc_log);

    let output = std::process::Command::new("sudo")
        .args(["systemctl", "restart", "karin-proxy-daemon.service"])
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        let log_output = std::process::Command::new("sudo")
            .args(["journalctl", "-u", "karin-proxy-daemon.service", "-n", "15", "--no-pager"])
            .output()
            .map_err(|_| "Не удалось прочитать логи".to_string())?;
            
        return Err(format!("Ядро упало при запуске. Лог:\n{}", String::from_utf8_lossy(&log_output.stdout)));
    }

    // --- ФИНАЛЬНАЯ МАГИЯ LINUX С ТУМБЛЕРОМ ---
    if allow_server_proxy {
        let ips_to_delete = resolved_ips.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            for ip in ips_to_delete {
                let _ = std::process::Command::new("sudo")
                    .args(["-n", "/usr/bin/ip", "rule", "del", "to", &ip, "lookup", "main"])
                    .output();
                
                let ip_32 = format!("{}/32", ip);
                let _ = std::process::Command::new("sudo")
                    .args(["-n", "/usr/bin/ip", "rule", "del", "to", &ip_32, "lookup", "main"])
                    .output();
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
        if let Some(token) = guard.as_ref() { 
            format!("http://karin:{}@127.0.0.1:2080", token) 
        } else { 
            "http://127.0.0.1:2080".to_string() 
        }
    };
    let proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let ip = client.get("http://ifconfig.me/ip")
        .send()
        .await
        .map_err(|e| format!("Ошибка сети: {}", e))?
        .text()
        .await
        .map_err(|_e| "Ошибка парсинга".to_string())?;
        
    Ok(ip)
}

#[tauri::command]
async fn check_ping(_state: State<'_, ProxyState>) -> Result<String, String> {
    let proxy_url = {
        let guard = _state.auth_token.lock().unwrap();
        if let Some(token) = guard.as_ref() { 
            format!("http://karin:{}@127.0.0.1:2080", token) 
        } else { 
            "http://127.0.0.1:2080".to_string() 
        }
    };
    let proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let start = std::time::Instant::now();
    let _ = client.get("http://cp.cloudflare.com/generate_204")
        .send()
        .await
        .map_err(|_e| "Ошибка сети".to_string())?; 
    
    Ok(format!("{} ms", start.elapsed().as_millis()))
}

#[tauri::command]
fn open_browser(url: String) {
    std::process::Command::new("xdg-open")
        .arg(url)
        .spawn()
        .ok();
}

// **********************************
// TAURI COMMANDS: LOGS & PROFILES
// **********************************
#[tauri::command]
fn get_logs() -> Result<String, String> {
    let (log_path, _) = get_log_paths();
    
    match std::fs::read_to_string(&log_path) {
        Ok(content) => {
            if content.trim().is_empty() {
                return Ok("Ожидание логов (Прокси работает, ожидаем сетевой трафик)...".to_string());
            }
            let lines: Vec<&str> = content.lines().collect();
            let last_lines = if lines.len() > 50 { &lines[lines.len() - 50..] } else { &lines[..] };
            Ok(last_lines.join("\n"))
        },
        Err(e) => {
            Ok(format!("Ошибка чтения логов: {}\nУбедитесь, что прокси запущен.", e))
        }
    }
}

#[tauri::command]
fn get_geosite_list() -> Vec<String> { 
    vec![
        "google", "youtube", "telegram", "vk", "yandex", "mailru",
        "github", "netflix", "spotify", "instagram", "twitter", "facebook",
        "tiktok", "apple", "microsoft", "amazon", "discord", "reddit", "twitch",
        "ru", "cn", "us", "geolocation-!cn", "geolocation-!ru",
        "category-ads-all", "category-porn", "category-games",
        "private", "speedtest", "openai"
    ].into_iter().map(String::from).collect() 
}

#[tauri::command]
fn clear_logs() -> Result<String, String> {
    let (err_log, acc_log) = get_log_paths();
    let _ = std::fs::write(&err_log, "");
    let _ = std::fs::write(&acc_log, "");
    Ok("Очищено".into())
}

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
    }).await.map_err(|e| format!("Ошибка потока: {}", e))?;

    result
}

// **********************************
// TAURI COMMANDS: WINDOW MANAGEMENT
// **********************************
#[tauri::command]
fn minimize_window(window: tauri::Window) {
    let _ = window.minimize();
}

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

#[tauri::command]
fn close_window(_window: tauri::Window, _state: State<'_, ProxyState>) {
    if let Ok(mut guard) = _state.auth_token.lock() { *guard = None; }
    teardown_connections();
    std::process::exit(0);
}

// **********************************
// MAIN APPLICATION ENTRY POINT
// **********************************
fn main() {
    tokio::runtime::Runtime::new().unwrap().block_on(async { 
        let _ = ensure_geo_files().await; 
    });

    let app = tauri::Builder::default()
        .manage(ProxyState { auth_token: Mutex::new(None) })
        .invoke_handler(tauri::generate_handler![
            start_proxy, 
            stop_proxy,
            fetch_subscription, 
            get_geosite_list, 
            get_logs, 
            clear_logs, 
            get_vpn_ip, 
            check_ping, 
            export_profile, 
            minimize_window, 
            maximize_window, 
            close_window,
            open_browser
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|_app_handle, event| {
        if let RunEvent::ExitRequested { .. } | RunEvent::Exit = event {
            let _ = std::process::Command::new("sudo").args(["systemctl", "stop", "karin-proxy-daemon.service"]).output();
            let _ = std::process::Command::new("sudo").args(["pkill", "-f", "/etc/karin-proxy/openvpn.ovpn"]).output();
            let _ = std::process::Command::new("sudo").args(["cp", "/etc/karin-proxy/resolv.conf.bak", "/etc/resolv.conf"]).output();
        }
    });
}