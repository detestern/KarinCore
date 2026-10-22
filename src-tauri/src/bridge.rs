//! Мостик для внешних оболочек (karin-shell / Brain Shell).
//!
//! Две части:
//!   1. статус-файл `${XDG_STATE_HOME:-~/.local/state}/karincore/shell.json`,
//!      из которого панель узнаёт состояние VPN, выбранный профиль и список профилей;
//!   2. флаги командной строки `--connect [id]`, `--disconnect`, `--select id`.
//!
//! Модуль намеренно использует только `std`: так его логику (id профиля, формат
//! файла, атомарная запись, разбор флагов) можно проверять юнит-тестами без tauri.
//! Склейка с tauri (команда для фронтенда, события, single-instance) лежит в main.rs.
//!
//! В файл никогда не попадают ссылки, ключи, UUID и пароли. Профиль описывается
//! стабильным несекретным id (первые 12 hex-символов sha256 от ссылки), именем,
//! типом и названием группы.

use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Версия формата статус-файла (поле `bridge`).
pub const BRIDGE_VERSION: u32 = 1;

// **********************************
// SHA-256 (для стабильного id профиля)
// **********************************
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Стабильный несекретный id профиля: первые 12 hex-символов sha256(ссылки).
pub fn profile_id(link: &str) -> String {
    let digest = sha256(link.as_bytes());
    let mut s = String::with_capacity(12);
    for b in digest.iter().take(6) {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// **********************************
// МОДЕЛЬ ДАННЫХ
// **********************************

/// Профиль в том виде, как он попадает в файл (без ссылки).
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileOut {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub group: String,
}

/// Профиль от фронтенда (со ссылкой: она нужна только для id и типа и дальше в файл не идёт).
#[derive(Clone, Debug)]
pub struct ProfileIn {
    pub url: String,
    pub name: String,
    pub group: String,
}

/// Снимок состояния от фронтенда.
#[derive(Clone, Debug)]
pub struct UpdateIn {
    pub state: String,
    pub selected_url: String,
    pub ip: String,
    pub profiles: Vec<ProfileIn>,
}

/// Что было в файле до запуска: чтобы панель не видела пустой список, пока фронтенд грузится.
#[derive(Clone, Debug, Default)]
pub struct Previous {
    pub selected: String,
    pub profile_name: String,
    pub profiles: Vec<ProfileOut>,
}

#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    pid: u32,
    state: String,
    selected: String,
    profile_name: String,
    ip: String,
    profiles: Vec<ProfileOut>,
}

impl Snapshot {
    fn empty(pid: u32) -> Self {
        Snapshot {
            pid,
            state: "disconnected".to_string(),
            selected: String::new(),
            profile_name: String::new(),
            ip: String::new(),
            profiles: Vec::new(),
        }
    }
}

/// Тип профиля по схеме ссылки.
pub fn link_kind(url: &str) -> String {
    let scheme = url.split("://").next().unwrap_or("").to_ascii_lowercase();
    match scheme.as_str() {
        "vless" => "vless",
        "vmess" => "vmess",
        "trojan" => "trojan",
        "ss" => "shadowsocks",
        "wg" => "wireguard",
        "ovpn" => "openvpn",
        other => return if other.is_empty() { "unknown".to_string() } else { other.to_string() },
    }
    .to_string()
}

/// Допустимые состояния; всё остальное считается «disconnected».
pub fn normalize_state(raw: &str) -> &'static str {
    match raw {
        "connecting" => "connecting",
        "connected" => "connected",
        _ => "disconnected",
    }
}

/// В файл попадает только настоящий IP-адрес: никаких «...», «Error» и прочего.
pub fn normalize_ip(raw: &str) -> String {
    let t = raw.trim();
    match t.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => String::new(),
    }
}

// **********************************
// JSON (вручную: нужны только строки, числа и массивы)
// **********************************
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn render_json(app_version: &str, snap: &Snapshot, updated: u64) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"bridge\": {},\n", BRIDGE_VERSION));
    s.push_str(&format!("  \"app_version\": {},\n", json_escape(app_version)));
    s.push_str(&format!("  \"pid\": {},\n", snap.pid));
    s.push_str(&format!("  \"state\": {},\n", json_escape(&snap.state)));
    s.push_str(&format!("  \"selected\": {},\n", json_escape(&snap.selected)));
    s.push_str(&format!("  \"profile_name\": {},\n", json_escape(&snap.profile_name)));
    s.push_str(&format!("  \"ip\": {},\n", json_escape(&snap.ip)));
    if snap.profiles.is_empty() {
        s.push_str("  \"profiles\": [],\n");
    } else {
        s.push_str("  \"profiles\": [\n");
        for (i, p) in snap.profiles.iter().enumerate() {
            s.push_str(&format!(
                "    {{ \"id\": {}, \"name\": {}, \"type\": {}, \"group\": {} }}{}\n",
                json_escape(&p.id),
                json_escape(&p.name),
                json_escape(&p.kind),
                json_escape(&p.group),
                if i + 1 < snap.profiles.len() { "," } else { "" }
            ));
        }
        s.push_str("  ],\n");
    }
    s.push_str(&format!("  \"updated\": {}\n", updated));
    s.push_str("}\n");
    s
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// **********************************
// ПУТЬ И АТОМАРНАЯ ЗАПИСЬ
// **********************************

/// `${XDG_STATE_HOME:-~/.local/state}/karincore/shell.json`.
/// Относительный XDG_STATE_HOME по спецификации XDG игнорируется.
pub fn state_file_path_from(xdg_state_home: Option<String>, home: Option<String>) -> Option<PathBuf> {
    let base = match xdg_state_home {
        Some(p) if !p.is_empty() && Path::new(&p).is_absolute() => PathBuf::from(p),
        _ => {
            let h = home.filter(|h| !h.is_empty())?;
            PathBuf::from(h).join(".local").join("state")
        }
    };
    Some(base.join("karincore").join("shell.json"))
}

#[cfg(not(windows))]
pub fn state_file_path() -> Option<PathBuf> {
    state_file_path_from(std::env::var("XDG_STATE_HOME").ok(), std::env::var("HOME").ok())
}

/// На Windows мост пока выключен: путь и проверку процесса добавим на одном из следующих этапов.
/// Без статус-файла приложение работает как обычно, флаги командной строки обрабатывает single-instance.
#[cfg(windows)]
pub fn state_file_path() -> Option<PathBuf> {
    None
}

/// Запись через `shell.json.tmp` и rename: читатель никогда не увидит половину файла.
pub fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent dir"))?;
    create_private_dir(dir)?;

    let mut tmp_name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);

    {
        let mut f = open_private(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.flush()?;
        let _ = f.sync_all();
    }
    fs::rename(&tmp, path)
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)
}

#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)
}

// **********************************
// ФЛАГИ КОМАНДНОЙ СТРОКИ
// **********************************
#[derive(Clone, Debug, PartialEq)]
pub enum CliAction {
    /// `--connect [id]`: выбрать профиль (если указан) и подключиться.
    Connect(Option<String>),
    /// `--disconnect`
    Disconnect,
    /// `--select id`: выбрать профиль без подключения.
    Select(String),
}

/// Разбор argv (первым элементом идёт имя программы). Неизвестные аргументы игнорируются.
pub fn parse_cli(args: &[String]) -> Vec<CliAction> {
    let mut out = Vec::new();
    let mut i = 1;
    let clean = |s: &str| s.trim().to_ascii_lowercase();
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--disconnect" {
            out.push(CliAction::Disconnect);
        } else if a == "--connect" {
            if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                out.push(CliAction::Connect(Some(clean(&args[i + 1]))));
                i += 1;
            } else {
                out.push(CliAction::Connect(None));
            }
        } else if let Some(id) = a.strip_prefix("--connect=") {
            let id = clean(id);
            out.push(CliAction::Connect(if id.is_empty() { None } else { Some(id) }));
        } else if a == "--select" {
            if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                out.push(CliAction::Select(clean(&args[i + 1])));
                i += 1;
            }
        } else if let Some(id) = a.strip_prefix("--select=") {
            let id = clean(id);
            if !id.is_empty() {
                out.push(CliAction::Select(id));
            }
        }
        i += 1;
    }
    out
}

/// Действие, готовое для фронтенда: id уже превращён в ссылку (она остаётся внутри приложения).
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedAction {
    pub action: &'static str,
    pub url: Option<String>,
}

// **********************************
// ЖИВОЙ ЛИ ЗАПУЩЕННЫЙ ЭКЗЕМПЛЯР
// **********************************

/// Достаёт `"pid": N` из текста статус-файла.
pub fn pid_from_text(text: &str) -> Option<u32> {
    let idx = text.find("\"pid\"")?;
    let rest = &text[idx + 5..];
    let colon = rest.find(':')?;
    let digits: String = rest[colon + 1..].trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u32>().ok()
}

fn pid_is_this_program(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let link = match fs::read_link(format!("/proc/{}/exe", pid)) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let theirs = link.to_string_lossy().trim_end_matches(" (deleted)").to_string();
    let mine = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().trim_end_matches(" (deleted)").to_string(),
        Err(_) => return false,
    };
    Path::new(&theirs).file_name() == Path::new(&mine).file_name()
}

/// `Some(true)`: по статус-файлу экземпляр запущен; `Some(false)`: файл есть, но процесса нет;
/// `None`: файла нет или он нечитаем (тогда решает single-instance).
pub fn running_instance_alive() -> Option<bool> {
    let path = state_file_path()?;
    let text = fs::read_to_string(path).ok()?;
    let pid = pid_from_text(&text)?;
    Some(pid_is_this_program(pid))
}

// **********************************
// СОСТОЯНИЕ МОСТА
// **********************************
struct Inner {
    snap: Snapshot,
    /// id → ссылка. Живёт только в памяти, на диск не попадает.
    links: Vec<(String, String)>,
    last_written: Option<String>,
    frontend_ready: bool,
    pending: Vec<CliAction>,
}

pub struct BridgeState {
    inner: Mutex<Inner>,
    path: Option<PathBuf>,
    app_version: String,
}

impl BridgeState {
    pub fn new(app_version: &str, pid: u32, path: Option<PathBuf>) -> Self {
        BridgeState {
            inner: Mutex::new(Inner {
                snap: Snapshot::empty(pid),
                links: Vec::new(),
                last_written: None,
                frontend_ready: false,
                pending: Vec::new(),
            }),
            path,
            app_version: app_version.to_string(),
        }
    }

    fn write_locked(&self, inner: &mut Inner, force: bool) {
        let path = match &self.path {
            Some(p) => p,
            None => return,
        };
        // Сравниваем без времени: иначе каждое повторное обновление переписывало бы файл.
        let key = render_json(&self.app_version, &inner.snap, 0);
        if !force && inner.last_written.as_deref() == Some(key.as_str()) {
            return;
        }
        let body = render_json(&self.app_version, &inner.snap, now_unix());
        match write_atomic(path, &body) {
            Ok(()) => inner.last_written = Some(key),
            Err(e) => eprintln!("[bridge] не удалось записать {}: {}", path.display(), e),
        }
    }

    /// Старт приложения: pid, состояние «disconnected» и (если есть) прежний список профилей.
    pub fn start(&self, previous: Option<Previous>) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(p) = previous {
            inner.snap.selected = p.selected;
            inner.snap.profile_name = p.profile_name;
            inner.snap.profiles = p.profiles;
        }
        inner.snap.state = "disconnected".to_string();
        inner.snap.ip.clear();
        self.write_locked(&mut inner, true);
    }

    /// Выход (в том числе по закрытию окна): pid 0, «disconnected», без IP.
    pub fn exit(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.snap.pid = 0;
        inner.snap.state = "disconnected".to_string();
        inner.snap.ip.clear();
        self.write_locked(&mut inner, true);
    }

    /// Снимок от фронтенда. Возвращает действия, которые ждали первого снимка.
    pub fn update(&self, u: UpdateIn) -> Vec<ResolvedAction> {
        let mut inner = self.inner.lock().unwrap();

        let mut profiles: Vec<ProfileOut> = Vec::new();
        let mut links: Vec<(String, String)> = Vec::new();
        for p in &u.profiles {
            let id = profile_id(&p.url);
            if links.iter().any(|(known, _)| *known == id) {
                continue; // одна и та же ссылка в двух группах: оставляем первую
            }
            links.push((id.clone(), p.url.clone()));
            profiles.push(ProfileOut { id, name: p.name.clone(), kind: link_kind(&p.url), group: p.group.clone() });
        }

        let selected = if u.selected_url.is_empty() { String::new() } else { profile_id(&u.selected_url) };
        let (selected, profile_name) = match profiles.iter().find(|p| p.id == selected) {
            Some(p) => (p.id.clone(), p.name.clone()),
            None => (String::new(), String::new()),
        };

        let state = normalize_state(&u.state);
        inner.snap.state = state.to_string();
        inner.snap.selected = selected;
        inner.snap.profile_name = profile_name;
        inner.snap.ip = if state == "connected" { normalize_ip(&u.ip) } else { String::new() };
        inner.snap.profiles = profiles;
        inner.links = links;
        inner.frontend_ready = true;

        self.write_locked(&mut inner, false);

        let pending = std::mem::take(&mut inner.pending);
        Self::resolve_all(&inner.links, pending)
    }

    /// Действия из командной строки. Пока фронтенд не прислал список профилей, они ждут.
    pub fn dispatch(&self, actions: Vec<CliAction>) -> Vec<ResolvedAction> {
        let mut inner = self.inner.lock().unwrap();
        if inner.frontend_ready {
            Self::resolve_all(&inner.links, actions)
        } else {
            inner.pending.extend(actions);
            Vec::new()
        }
    }

    fn resolve_all(links: &[(String, String)], actions: Vec<CliAction>) -> Vec<ResolvedAction> {
        let find = |id: &str| links.iter().find(|(known, _)| known == id).map(|(_, url)| url.clone());
        let mut out = Vec::new();
        for a in actions {
            match a {
                CliAction::Disconnect => out.push(ResolvedAction { action: "disconnect", url: None }),
                CliAction::Connect(None) => out.push(ResolvedAction { action: "connect", url: None }),
                CliAction::Connect(Some(id)) => match find(&id) {
                    Some(url) => out.push(ResolvedAction { action: "connect", url: Some(url) }),
                    None => eprintln!("[bridge] --connect: профиль {} не найден", id),
                },
                CliAction::Select(id) => match find(&id) {
                    Some(url) => out.push(ResolvedAction { action: "select", url: Some(url) }),
                    None => eprintln!("[bridge] --select: профиль {} не найден", id),
                },
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("karincore-bridge-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn pin(url: &str, name: &str, group: &str) -> ProfileIn {
        ProfileIn { url: url.to_string(), name: name.to_string(), group: group.to_string() }
    }

    fn upd(state: &str, selected: &str, ip: &str, profiles: Vec<ProfileIn>) -> UpdateIn {
        UpdateIn { state: state.to_string(), selected_url: selected.to_string(), ip: ip.to_string(), profiles }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // длина около границы блока (55, 56, 64 байта)
        assert_eq!(
            hex(&sha256(&vec![b'a'; 56])),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
        assert_eq!(
            hex(&sha256(&vec![b'a'; 64])),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
    }

    #[test]
    fn profile_id_is_12_hex_prefix_of_sha256() {
        assert_eq!(profile_id("abc"), "ba7816bf8f01");
        let id = profile_id("vless://secret-uuid@host:443?type=tcp#Name");
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(id, profile_id("vless://secret-uuid@host:443?type=tcp#Name"));
        assert_ne!(id, profile_id("vless://secret-uuid@host:443?type=tcp#Name2"));
    }

    #[test]
    fn link_kinds() {
        assert_eq!(link_kind("vless://x@h:1"), "vless");
        assert_eq!(link_kind("VMESS://abc"), "vmess");
        assert_eq!(link_kind("trojan://p@h:1"), "trojan");
        assert_eq!(link_kind("ss://abc"), "shadowsocks");
        assert_eq!(link_kind("wg://h:51820?name=x"), "wireguard");
        assert_eq!(link_kind("ovpn://h?name=x"), "openvpn");
        assert_eq!(link_kind(""), "unknown");
    }

    #[test]
    fn state_and_ip_are_sanitised() {
        assert_eq!(normalize_state("connected"), "connected");
        assert_eq!(normalize_state("connecting"), "connecting");
        assert_eq!(normalize_state("weird"), "disconnected");
        assert_eq!(normalize_ip(" 203.0.113.5\n"), "203.0.113.5");
        assert_eq!(normalize_ip("2001:db8::1"), "2001:db8::1");
        assert_eq!(normalize_ip("..."), "");
        assert_eq!(normalize_ip("Error"), "");
        assert_eq!(normalize_ip("<html>"), "");
    }

    #[test]
    fn json_escaping() {
        assert_eq!(json_escape("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(json_escape("\u{1}"), "\"\\u0001\"");
        assert_eq!(json_escape("Нидерланды 🇳🇱"), "\"Нидерланды 🇳🇱\"");
    }

    // Пути XDG в тесте записаны по-unix'овому; на Windows путь моста будет другим.
    #[cfg(unix)]
    #[test]
    fn state_path_rules() {
        assert_eq!(
            state_file_path_from(Some("/x/state".into()), Some("/home/u".into())),
            Some(PathBuf::from("/x/state/karincore/shell.json"))
        );
        assert_eq!(
            state_file_path_from(None, Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.local/state/karincore/shell.json"))
        );
        assert_eq!(
            state_file_path_from(Some("".into()), Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.local/state/karincore/shell.json"))
        );
        // относительный путь по спецификации XDG игнорируется
        assert_eq!(
            state_file_path_from(Some("relative/dir".into()), Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.local/state/karincore/shell.json"))
        );
        assert_eq!(state_file_path_from(None, None), None);
    }

    #[test]
    fn cli_parsing() {
        assert_eq!(parse_cli(&s(&["karincore"])), vec![]);
        assert_eq!(parse_cli(&s(&["karincore", "--connect"])), vec![CliAction::Connect(None)]);
        assert_eq!(
            parse_cli(&s(&["karincore", "--connect", "ABC123def456"])),
            vec![CliAction::Connect(Some("abc123def456".into()))]
        );
        assert_eq!(
            parse_cli(&s(&["karincore", "--connect=abc123def456"])),
            vec![CliAction::Connect(Some("abc123def456".into()))]
        );
        assert_eq!(parse_cli(&s(&["karincore", "--disconnect"])), vec![CliAction::Disconnect]);
        assert_eq!(
            parse_cli(&s(&["karincore", "--select", "abc123def456"])),
            vec![CliAction::Select("abc123def456".into())]
        );
        assert_eq!(parse_cli(&s(&["karincore", "--select"])), vec![]);
        // --connect не съедает следующий флаг
        assert_eq!(
            parse_cli(&s(&["karincore", "--connect", "--disconnect"])),
            vec![CliAction::Connect(None), CliAction::Disconnect]
        );
        // выбор и подключение одной командой, порядок сохраняется
        assert_eq!(
            parse_cli(&s(&["karincore", "--select", "aaa", "--connect"])),
            vec![CliAction::Select("aaa".into()), CliAction::Connect(None)]
        );
        // неизвестное игнорируется, argv[0] не разбирается
        assert_eq!(parse_cli(&s(&["--connect", "--foo", "bar"])), vec![]);
        assert_eq!(parse_cli(&s(&["karincore", "--foo", "bar"])), vec![]);
    }

    #[test]
    fn pid_extraction() {
        assert_eq!(pid_from_text("{\n  \"bridge\": 1,\n  \"pid\": 4242,\n  \"state\": \"x\"\n}"), Some(4242));
        assert_eq!(pid_from_text("{\"pid\":0}"), Some(0));
        assert_eq!(pid_from_text("{}"), None);
        assert_eq!(pid_from_text("garbage"), None);
    }

    #[test]
    fn atomic_write_replaces_file_and_leaves_no_tmp() {
        let dir = tmp_dir("atomic");
        let path = dir.join("karincore").join("shell.json");
        write_atomic(&path, "one").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "one");
        write_atomic(&path, "two").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two");
        assert!(!path.with_file_name("shell.json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_has_the_documented_shape_and_no_secrets() {
        let dir = tmp_dir("shape");
        let path = dir.join("karincore").join("shell.json");
        let st = BridgeState::new("1.4.0", 4242, Some(path.clone()));
        st.start(None);

        let secret_a = "vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?type=tcp&pbk=SECRETKEY#NL";
        let secret_b = "trojan://hunter2pass@fi.example.com:443#Finland";
        st.update(upd(
            "connected",
            secret_a,
            "203.0.113.5",
            vec![pin(secret_a, "NL (nl.example.com)", "provider"), pin(secret_b, "Finland", "")],
        ));

        let text = fs::read_to_string(&path).unwrap();
        for forbidden in ["11111111-2222", "SECRETKEY", "hunter2pass", "vless://", "trojan://", "pbk="] {
            assert!(!text.contains(forbidden), "в файл попало секретное: {}", forbidden);
        }
        let id_a = profile_id(secret_a);
        let id_b = profile_id(secret_b);
        assert!(text.contains("\"bridge\": 1"));
        assert!(text.contains("\"app_version\": \"1.4.0\""));
        assert!(text.contains("\"pid\": 4242"));
        assert!(text.contains("\"state\": \"connected\""));
        assert!(text.contains(&format!("\"selected\": \"{}\"", id_a)));
        assert!(text.contains("\"profile_name\": \"NL (nl.example.com)\""));
        assert!(text.contains("\"ip\": \"203.0.113.5\""));
        assert!(text.contains(&format!("{{ \"id\": \"{}\", \"name\": \"NL (nl.example.com)\", \"type\": \"vless\", \"group\": \"provider\" }}", id_a)));
        assert!(text.contains(&format!("{{ \"id\": \"{}\", \"name\": \"Finland\", \"type\": \"trojan\", \"group\": \"\" }}", id_b)));
        assert!(text.contains("\"updated\": "));
        // порядок ключей из спецификации
        let order = ["\"bridge\"", "\"app_version\"", "\"pid\"", "\"state\"", "\"selected\"", "\"profile_name\"", "\"ip\"", "\"profiles\"", "\"updated\""];
        let mut last = 0;
        for k in order {
            let at = text.find(k).unwrap();
            assert!(at >= last, "ключ {} не на своём месте", k);
            last = at;
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ip_is_dropped_unless_connected() {
        let dir = tmp_dir("ip");
        let path = dir.join("karincore").join("shell.json");
        let st = BridgeState::new("1.4.0", 7, Some(path.clone()));
        st.start(None);
        let a = "vless://u@h:1#A";
        st.update(upd("connecting", a, "203.0.113.5", vec![pin(a, "A", "")]));
        assert!(fs::read_to_string(&path).unwrap().contains("\"ip\": \"\""));
        st.update(upd("connected", a, "203.0.113.5", vec![pin(a, "A", "")]));
        assert!(fs::read_to_string(&path).unwrap().contains("\"ip\": \"203.0.113.5\""));
        st.update(upd("disconnected", a, "203.0.113.5", vec![pin(a, "A", "")]));
        assert!(fs::read_to_string(&path).unwrap().contains("\"ip\": \"\""));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exit_writes_pid_zero_and_clears_state_but_keeps_profiles() {
        let dir = tmp_dir("exit");
        let path = dir.join("karincore").join("shell.json");
        let st = BridgeState::new("1.4.0", 99, Some(path.clone()));
        st.start(None);
        let a = "ss://abc#A";
        st.update(upd("connected", a, "198.51.100.7", vec![pin(a, "A", "g")]));
        st.exit();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"pid\": 0"));
        assert!(text.contains("\"state\": \"disconnected\""));
        assert!(text.contains("\"ip\": \"\""));
        assert!(text.contains(&profile_id(a)));
        assert_eq!(pid_from_text(&text), Some(0));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_keeps_previous_profiles_until_frontend_reports() {
        let dir = tmp_dir("prev");
        let path = dir.join("karincore").join("shell.json");
        let st = BridgeState::new("1.4.0", 5, Some(path.clone()));
        st.start(Some(Previous {
            selected: "aaaaaaaaaaaa".into(),
            profile_name: "Old".into(),
            profiles: vec![ProfileOut { id: "aaaaaaaaaaaa".into(), name: "Old".into(), kind: "vless".into(), group: "".into() }],
        }));
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"pid\": 5"));
        assert!(text.contains("\"state\": \"disconnected\""));
        assert!(text.contains("aaaaaaaaaaaa"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unchanged_snapshot_does_not_rewrite_the_file() {
        let dir = tmp_dir("dedup");
        let path = dir.join("karincore").join("shell.json");
        let st = BridgeState::new("1.4.0", 5, Some(path.clone()));
        st.start(None);
        let a = "vless://u@h:1#A";
        st.update(upd("connected", a, "203.0.113.5", vec![pin(a, "A", "")]));
        // подменяем файл «чужим» содержимым: повторный одинаковый снимок его трогать не должен
        fs::write(&path, "MARK").unwrap();
        st.update(upd("connected", a, "203.0.113.5", vec![pin(a, "A", "")]));
        assert_eq!(fs::read_to_string(&path).unwrap(), "MARK");
        // а изменение — переписывает
        st.update(upd("disconnected", a, "", vec![pin(a, "A", "")]));
        assert_ne!(fs::read_to_string(&path).unwrap(), "MARK");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_links_get_one_entry_and_unknown_selection_is_empty() {
        let dir = tmp_dir("dup");
        let path = dir.join("karincore").join("shell.json");
        let st = BridgeState::new("1.4.0", 5, Some(path.clone()));
        st.start(None);
        let a = "vless://u@h:1#A";
        st.update(upd("disconnected", "vless://not-in-list@h:1#X", "", vec![pin(a, "A", "g1"), pin(a, "A", "g2")]));
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches(&profile_id(a)).count(), 1);
        assert!(text.contains("\"selected\": \"\""));
        assert!(text.contains("\"profile_name\": \"\""));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cold_start_actions_wait_for_the_first_snapshot() {
        let st = BridgeState::new("1.4.0", 5, None);
        let a = "vless://u@h:1#A";
        let id = profile_id(a);
        assert!(st.dispatch(vec![CliAction::Connect(Some(id.clone()))]).is_empty());
        let out = st.update(upd("disconnected", "", "", vec![pin(a, "A", "")]));
        assert_eq!(out, vec![ResolvedAction { action: "connect", url: Some(a.to_string()) }]);
        // после этого действия идут сразу
        let now = st.dispatch(vec![CliAction::Select(id.clone()), CliAction::Disconnect, CliAction::Connect(None)]);
        assert_eq!(
            now,
            vec![
                ResolvedAction { action: "select", url: Some(a.to_string()) },
                ResolvedAction { action: "disconnect", url: None },
                ResolvedAction { action: "connect", url: None },
            ]
        );
        // неизвестный id пропускается
        assert!(st.dispatch(vec![CliAction::Connect(Some("000000000000".into()))]).is_empty());
        assert!(st.dispatch(vec![CliAction::Select("000000000000".into())]).is_empty());
    }
}
