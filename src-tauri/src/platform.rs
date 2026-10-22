//! Платформенный слой GUI: то, что на Linux и Windows делается по-разному.
//! Всё остальное в main.rs общее для обеих систем.
//!
//! Windows-версия пока на первом этапе: интерфейс работает, а привилегированной службы,
//! которая поднимает туннель, ещё нет. Поэтому подключение возвращает понятное сообщение,
//! а не ошибку о ненайденном Xray или sudo.

/// Почему подключение на этой платформе пока недоступно (`None` — доступно).
#[cfg(windows)]
pub const CONNECT_UNAVAILABLE: Option<&str> = Some(
    "Подключение в Windows-версии появится в одной из следующих альфа-сборок. \
     Пока можно добавить серверы и подписки и настроить маршрутизацию: всё сохранится.",
);
#[cfg(not(windows))]
pub const CONNECT_UNAVAILABLE: Option<&str> = None;

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
