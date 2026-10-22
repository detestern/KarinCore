//! Платформенный слой GUI: то, что на Linux и Windows делается по-разному.
//! Всё остальное в main.rs общее для обеих систем.
//!
//! Windows-версия сейчас на этапе 2: служба KarinCore запускает Xray от SYSTEM, но без TUN.
//! Ядро работает как локальный прокси (пинг и «мой IP» идут через него), а весь остальной
//! трафик системы через туннель пока не направляется — это следующий этап.

use serde_json::Value;

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

/// Приводит конфиг Xray, собранный для Linux, к тому, что сейчас умеет Windows-версия:
/// без TUN и без DNS-слушателя на 127.0.0.1:53 (их заменит TUN-адаптер на следующем этапе)
/// и без `sockopt.mark` (меток пакетов в Windows нет).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn strip_for_windows(config: &mut Value) {
    if let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) {
        inbounds.retain(|ib| !matches!(ib.get("tag").and_then(Value::as_str), Some("tun-in") | Some("dns-in")));
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
}

#[cfg(windows)]
pub fn adapt_core_config(config: &mut Value) {
    strip_for_windows(config);
}

#[cfg(not(windows))]
pub fn adapt_core_config(_config: &mut Value) {}

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
    use serde_json::json;

    #[test]
    fn windows_config_has_no_tun_dns_listener_or_marks() {
        let mut c = json!({
            "inbounds": [
                { "tag": "mixed", "port": 2080 },
                { "tag": "tun-in", "protocol": "tun" },
                { "tag": "dns-in", "port": 53 },
                { "tag": "ping-in", "port": 2082 }
            ],
            "outbounds": [
                { "tag": "proxy", "streamSettings": { "network": "tcp", "sockopt": { "mark": 255 } } },
                { "tag": "direct", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": 255 } } },
                { "tag": "vpn", "streamSettings": { "sockopt": { "mark": 111, "interface": "wg0" } } },
                { "tag": "block", "protocol": "blackhole" }
            ]
        });
        strip_for_windows(&mut c);
        let tags: Vec<&str> = c["inbounds"].as_array().unwrap().iter().map(|i| i["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, vec!["mixed", "ping-in"]);
        assert_eq!(c["outbounds"][0]["streamSettings"], json!({ "network": "tcp" }));
        assert!(c["outbounds"][1].get("streamSettings").is_none());
        assert_eq!(c["outbounds"][2]["streamSettings"]["sockopt"], json!({ "interface": "wg0" }));
        assert!(!c.to_string().contains("mark"));
    }
}
