//! Платформенный слой GUI: то, что на Linux и Windows делается по-разному.
//! Всё остальное в main.rs общее для обеих систем.
//!
//! Windows-версия сейчас на этапе 3: служба KarinCore запускает Xray от SYSTEM, и весь трафик
//! системы идёт через TUN-адаптер Wintun. Kill Switch, OpenVPN и WireGuard — следующие этапы.

use serde_json::{json, Value};

/// Проверять Xray и докачивать geo-базы при запуске приложения. На Windows Xray и geo-базы
/// кладёт установщик рядом со службой, а наличие xray.exe проверяет сама служба.
pub const PREPARE_CORE_AT_START: bool = cfg!(not(windows));

/// Отказ в том, что эта платформа пока не умеет. Отказ Kill Switch идёт с префиксом
/// `ks_prefix` (KS_FAILED:), чтобы интерфейс показал его в окне Kill Switch.
#[cfg(windows)]
pub fn check_connect_supported(link: &str, kill_switch: bool, ks_prefix: &str) -> Result<(), String> {
    if link.starts_with("ovpn://") || link.starts_with("wg://") {
        return Err("OpenVPN и WireGuard появятся в Windows-версии позже. Сейчас подключаются VLESS, VMess, Trojan и Shadowsocks.".into());
    }
    if kill_switch {
        // Защита либо включена полностью, либо подключение не стартует.
        return Err(format!(
            "{}Kill Switch в Windows-версии ещё не готов. Выключите его в настройках, чтобы подключиться.",
            ks_prefix
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn check_connect_supported(_link: &str, _kill_switch: bool, _ks_prefix: &str) -> Result<(), String> {
    Ok(())
}

// **********************************
// TUN НА WINDOWS
// **********************************
// На Linux маршруты и DNS настраивает route.sh, а петлю разрывает метка пакетов (mark 255).
// На Windows всё это делает сам Xray (26.9.30+) по полям TUN-inbound:
//   * gateway — адреса адаптера (IPv4 и IPv6, иначе IPv6 через туннель не пойдёт);
//   * autoSystemRoutingTable — весь трафик в адаптер. Половинки (0/1 + 128/1) точнее любого
//     маршрута по умолчанию, поэтому выигрывают у него независимо от метрик; локальная сеть
//     остаётся напрямую, потому что её маршруты ещё точнее;
//   * autoOutboundsInterface: "auto" — собственные соединения Xray привязаны к физическому
//     адаптеру (замена mark 255), Xray сам следит за сменой сети;
//   * dns — DNS-сервер адаптера: адрес внутри подсети туннеля, запросы к нему отвечает
//     DNS-модуль Xray (как 127.0.0.1:53 на Linux);
//   * autoSystemWfpBlockLeak — WFP-фильтры: DNS (порт 53) не уходит мимо туннеля, в том числе
//     от службы DNS-клиента Windows, которая иначе спрашивает все адаптеры сразу.
//     Если фильтры не встали, Xray не запускается: лучше без туннеля, чем с утечкой.
// Всё это живёт, пока работает xray.exe: адаптер, маршруты, DNS и фильтры исчезают вместе с ним.

/// Имя адаптера Wintun в «Сетевых подключениях».
pub const WIN_TUN_NAME: &str = "karincore";
/// DNS-сервер адаптера (внутри подсети 172.19.0.0/30, на адаптере 172.19.0.1).
pub const WIN_TUN_DNS: &str = "172.19.0.2";

/// `ipv6` — включён ли IPv6 в системе. Если его отключили (DisabledComponents), адрес и
/// маршруты IPv6 на адаптер не ставятся: иначе Xray не запустится. IPv6 мимо туннеля при этом
/// всё равно не уйдёт — его целиком блокирует `misconfigtun`.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_tun_settings(ipv6: bool) -> Value {
    let (gateway, routes) = if ipv6 {
        (json!(["172.19.0.1/30", "fd00:19::1/126"]), json!(["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]))
    } else {
        (json!(["172.19.0.1/30"]), json!(["0.0.0.0/1", "128.0.0.0/1"]))
    };
    json!({
        "name": WIN_TUN_NAME,
        "mtu": 1500,
        "gateway": gateway,
        "dns": [WIN_TUN_DNS],
        "autoSystemRoutingTable": routes,
        "autoOutboundsInterface": "auto",
        "autoSystemWfpBlockLeak": ["dns", "misconfigtun"]
    })
}

/// IPv6 отключён в реестре для обычных (не туннельных) адаптеров — к ним относится и Wintun.
/// https://learn.microsoft.com/troubleshoot/windows-server/networking/configure-ipv6-in-windows
#[cfg(windows)]
fn ipv6_disabled() -> bool {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let key = wide(r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters");
    let name = wide("DisabledComponents");
    let mut value = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: строки с нулём на конце, буфер — u32 нужного размера.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    rc == 0 && value & 0x10 != 0
}

/// Приводит конфиг Xray, собранный для Linux, к Windows:
/// TUN-inbound настраивает систему сам (см. выше), DNS-слушателя на 127.0.0.1:53 нет —
/// его роль играет DNS-адрес адаптера; `sockopt.mark` убирается (меток в Windows нет).
/// Если «проксировать IP сервера» выключено, трафик других программ к адресам сервера
/// идёт напрямую, как исключение маршрута для сервера в route.sh.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn windows_config(config: &mut Value, server_ips: &[String], allow_server_proxy: bool, ipv6: bool) {
    if let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) {
        inbounds.retain(|ib| ib.get("tag").and_then(Value::as_str) != Some("dns-in"));
        for ib in inbounds.iter_mut() {
            if ib.get("tag").and_then(Value::as_str) == Some("tun-in") {
                ib["settings"] = windows_tun_settings(ipv6);
            }
        }
    }
    if let Some(outbounds) = config.get_mut("outbounds").and_then(Value::as_array_mut) {
        for ob in outbounds {
            let Some(stream) = ob.get_mut("streamSettings").and_then(Value::as_object_mut) else { continue };
            let empty = match stream.get_mut("sockopt").and_then(Value::as_object_mut) {
                Some(sockopt) => {
                    sockopt.remove("mark");
                    sockopt.is_empty()
                }
                None => false,
            };
            if empty {
                stream.remove("sockopt");
            }
            if stream.is_empty() {
                if let Some(o) = ob.as_object_mut() {
                    o.remove("streamSettings");
                }
            }
        }
    }
    if let Some(rules) = config.pointer_mut("/routing/rules").and_then(Value::as_array_mut) {
        let mut first = vec![json!({
            "type": "field", "inboundTag": ["tun-in"], "ip": [WIN_TUN_DNS], "port": "53", "outboundTag": "dns-out"
        })];
        let ips: Vec<&String> = server_ips.iter().filter(|s| s.parse::<std::net::IpAddr>().is_ok()).collect();
        if !allow_server_proxy && !ips.is_empty() {
            first.push(json!({ "type": "field", "inboundTag": ["tun-in"], "ip": ips, "outboundTag": "direct" }));
        }
        rules.splice(0..0, first);
    }
}

#[cfg(windows)]
pub fn adapt_core_config(config: &mut Value, server_ips: &[String], allow_server_proxy: bool) {
    windows_config(config, server_ips, allow_server_proxy, !ipv6_disabled());
}

#[cfg(not(windows))]
pub fn adapt_core_config(_config: &mut Value, _server_ips: &[String], _allow_server_proxy: bool) {}

// **********************************
// ЖУРНАЛЫ
// **********************************
/// Пути error.log и access.log Xray. Служба/helper всё равно подставляет свои фиксированные
/// пути в конфиг; здесь они нужны, чтобы GUI читал журналы.
#[cfg(not(windows))]
pub fn log_paths() -> (String, String) {
    ("/var/log/karin-proxy/error.log".to_string(), "/var/log/karin-proxy/access.log".to_string())
}

#[cfg(windows)]
pub fn log_paths() -> (String, String) {
    let base = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"))
        .join("KarinCore")
        .join("logs");
    (
        base.join("error.log").to_string_lossy().into_owned(),
        base.join("access.log").to_string_lossy().into_owned(),
    )
}

/// Почему журнал не читается (нет прав) — на Windows его открывают только тому, кто подключил VPN.
#[cfg(windows)]
pub fn log_access_message() -> String {
    "Нет доступа к журналам: их может читать только пользователь, который подключил VPN. Подключитесь, и журналы появятся.".to_string()
}

/// Плагины Tauri, которые нужны только этой платформе.
pub fn register_plugins<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    // Плагины используются только из Rust: в capabilities для них разрешений нет,
    // поэтому из WebView их команды недоступны.
    #[cfg(windows)]
    let builder = builder
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init());
    builder
}

// **********************************
// ССЫЛКИ
// **********************************
#[cfg(not(windows))]
pub fn open_url(url: &str) {
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

/// На Windows «открыть» умеет запускать файлы и программы, поэтому пропускаем только веб-ссылки.
#[cfg(windows)]
pub fn open_url(url: &str) {
    let Ok(parsed) = url::Url::parse(url) else {
        return;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return;
    }
    let _ = tauri_plugin_opener::open_url(parsed.as_str(), None::<&str>);
}

// **********************************
// УВЕДОМЛЕНИЯ
// **********************************
// Если уведомление показать не удалось, ничего не делаем: то же сообщение есть в самом приложении.
#[cfg(not(windows))]
pub fn notify(_app: &tauri::AppHandle, title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .args(["-a", "KarinCore", "--"])
        .arg(title)
        .arg(body)
        .spawn();
}

#[cfg(windows)]
pub fn notify(app: &tauri::AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title(title).body(body).show();
}

// **********************************
// БУФЕР ОБМЕНА
// **********************************
// Для кнопки «Вставить», если WebView не дал прочитать буфер сам.
#[cfg(not(windows))]
pub fn read_clipboard(_app: &tauri::AppHandle) -> Option<String> {
    // wl-paste (Wayland), затем xclip и xsel (X11).
    let attempts: [(&str, &[&str]); 3] = [
        ("wl-paste", &["--no-newline"]),
        ("xclip", &["-o", "-selection", "clipboard"]),
        ("xsel", &["-ob"]),
    ];
    for (program, args) in attempts {
        let Ok(output) = std::process::Command::new(program).args(args).output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        if !text.trim().is_empty() {
            return Some(text);
        }
    }
    None
}

#[cfg(windows)]
pub fn read_clipboard(app: &tauri::AppHandle) -> Option<String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    app.clipboard().read_text().ok()
}

// **********************************
// ЯДРО
// **********************************
/// Запущен ли Xray: "yes", "no" или "na" (неизвестно).
#[cfg(not(windows))]
pub fn core_running() -> &'static str {
    match std::process::Command::new("pgrep")
        .args(["-x", "xray"])
        .status()
    {
        Ok(status) if status.success() => "yes",
        Ok(_) => "no",
        Err(_) => "na",
    }
}

/// На Windows состояние ядра будет сообщать служба (следующий этап).
#[cfg(windows)]
pub fn core_running() -> &'static str {
    "na"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_config() -> Value {
        json!({
            "routing": { "rules": [
                { "type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out" },
                { "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }
            ] },
            "inbounds": [
                { "tag": "mixed", "port": 2080 },
                { "tag": "tun-in", "protocol": "tun", "settings": { "name": "tun0", "mtu": 1500, "gateway": ["172.19.0.1/30"] } },
                { "tag": "dns-in", "port": 53 },
                { "tag": "ping-in", "port": 2082 }
            ],
            "outbounds": [
                { "tag": "proxy", "streamSettings": { "network": "tcp", "sockopt": { "mark": 255 } } },
                { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 255 } } },
                { "tag": "vpn", "streamSettings": { "sockopt": { "mark": 111, "interface": "wg0" } } },
                { "tag": "block", "protocol": "blackhole" }
            ]
        })
    }

    #[test]
    fn windows_tun_replaces_route_sh_and_marks() {
        let mut c = linux_config();
        windows_config(&mut c, &["203.0.113.5".into(), "2001:db8::1".into(), "host.example".into()], false, true);
        let tags: Vec<&str> = c["inbounds"].as_array().unwrap().iter().map(|i| i["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, vec!["mixed", "tun-in", "ping-in"]);
        let tun = &c["inbounds"][1]["settings"];
        assert_eq!(tun["name"], "karincore");
        assert_eq!(tun["autoOutboundsInterface"], "auto");
        assert_eq!(tun["dns"], json!(["172.19.0.2"]));
        assert_eq!(tun["autoSystemWfpBlockLeak"], json!(["dns", "misconfigtun"]));
        assert_eq!(tun["autoSystemRoutingTable"], json!(["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]));
        assert_eq!(tun["gateway"], json!(["172.19.0.1/30", "fd00:19::1/126"]));
        assert_eq!(c["outbounds"][0]["streamSettings"], json!({ "network": "tcp" }));
        assert!(c["outbounds"][1].get("streamSettings").is_none());
        assert_eq!(c["outbounds"][2]["streamSettings"]["sockopt"], json!({ "interface": "wg0" }));
        assert!(!c.to_string().contains("mark"));
        let rules = c["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "dns-out");
        assert_eq!(rules[0]["ip"], json!(["172.19.0.2"]));
        assert_eq!(rules[1]["ip"], json!(["203.0.113.5", "2001:db8::1"]));
        assert_eq!(rules[1]["outboundTag"], "direct");
        assert_eq!(rules.len(), 4);
    }

    #[test]
    fn server_ip_goes_through_tunnel_when_allowed() {
        let mut c = linux_config();
        windows_config(&mut c, &["203.0.113.5".into()], true, true);
        let rules = c["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        assert!(!c.to_string().contains("203.0.113.5"));
    }

    #[test]
    fn without_ipv6_no_v6_address_or_routes_but_leak_block_stays() {
        let mut c = linux_config();
        windows_config(&mut c, &[], false, false);
        let tun = &c["inbounds"][1]["settings"];
        assert_eq!(tun["gateway"], json!(["172.19.0.1/30"]));
        assert_eq!(tun["autoSystemRoutingTable"], json!(["0.0.0.0/1", "128.0.0.0/1"]));
        assert_eq!(tun["autoSystemWfpBlockLeak"], json!(["dns", "misconfigtun"]));
    }
}
