//! Менеджер маршрутизации: поиск адресов, из-за которых сайт или видео не работает.
//!
//! На десктопе Xray всегда пишет error.log (уровень debug), поэтому поиск читает только
//! то, что дописано после его старта. На Android журнал по умолчанию выключен: на время
//! поиска ядро запускается с debug-журналом в папке приложения (см. `log_override`),
//! а после поиска файл стирается и ядро возвращается к обычному режиму.
//! Счётчики держатся в памяти и сбрасываются при остановке. Адреса нигде не сохраняются.
//!
//! Отсев шума:
//! - реклама и аналитика (geosite `category-ads-all` плюс небольшой встроенный список);
//! - адреса, которые уже покрыты правилами пользователя (domain/full/keyword/geosite/ip);
//! - «фон» — всё, что открылось до действия, из-за которого возникла проблема.
//!
//! Остальное группируется по домену верхнего уровня (`cdn.example.com` -> `example.com`).
//! Общие CDN не группируются: правило на них заденет чужие сайты.

use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;
#[cfg(target_os = "android")]
use tauri::Manager;
use tauri::{AppHandle, State};

#[cfg(not(target_os = "android"))]
const DEFAULT_GEOSITE_PATH: &str = "/etc/karin-proxy/geo/geosite.dat";
#[cfg(target_os = "android")]
const DEFAULT_GEOSITE_PATH: &str = "geosite.dat";

static GEOSITE_PATH: Mutex<Option<String>> = Mutex::new(None);
static LOG_OVERRIDE: Mutex<Option<String>> = Mutex::new(None);

/// Путь debug-журнала, который нужно включить в конфиге ядра, пока идёт поиск (только Android).
pub fn log_override() -> Option<String> {
    LOG_OVERRIDE.lock().ok().and_then(|g| g.clone())
}

fn set_log_override(path: Option<String>) {
    if let Ok(mut g) = LOG_OVERRIDE.lock() {
        *g = path;
    }
}
/// За один опрос читаем не больше этого объёма новых байт (остальное пропускаем с начала).
const MAX_READ: u64 = 16 * 1024 * 1024;
const MAX_SESSIONS: usize = 200_000;
const MAX_HOSTS: usize = 20_000;
const ADS_TAG: &str = "category-ads-all";

/// Резерв на случай, если geosite.dat ещё не скачан.
const BUILTIN_ADS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googleadservices.com",
    "adservice.google.com",
    "mc.yandex.ru",
    "an.yandex.ru",
    "yandexadexchange.net",
    "scorecardresearch.com",
    "hotjar.com",
    "clarity.ms",
    "adnxs.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "top-fwz1.mail.ru",
    "counter.yadro.ru",
];

/// Составные публичные суффиксы (минимальный список, без полной базы PSL).
const MULTI_SUFFIXES: &[&str] = &[
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "co.kr",
    "co.in",
    "co.za",
    "co.nz",
    "com.br",
    "com.cn",
    "com.hk",
    "com.tw",
    "com.tr",
    "com.ua",
    "com.mx",
    "com.ar",
    "com.sg",
    "com.pl",
    "com.ru",
    "spb.ru",
    "msk.ru",
    // Платформы, где каждый поддомен — отдельный чужой сайт.
    "github.io",
    "gitlab.io",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "herokuapp.com",
    "appspot.com",
    "blogspot.com",
    "web.app",
    "firebaseapp.com",
    "azurewebsites.net",
];

/// Общие CDN и облака: правило на них заденет чужие сайты.
const SHARED_HOSTS: &[&str] = &[
    "cloudfront.net",
    "akamaihd.net",
    "akamaized.net",
    "akamai.net",
    "edgekey.net",
    "edgesuite.net",
    "fastly.net",
    "fastlylb.net",
    "azureedge.net",
    "amazonaws.com",
    "googleusercontent.com",
    "gstatic.com",
    "googleapis.com",
    "b-cdn.net",
    "cdn77.org",
    "stackpathcdn.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "cloudflare.net",
    "llnwd.net",
    "edgecastcdn.net",
    "hwcdn.net",
    "cdn.jsdelivr.net",
    "sharedhost.net",
];

// **********************************
// РАЗБОР ЖУРНАЛОВ
// **********************************
const OUT_PROXY: usize = 0;
const OUT_DIRECT: usize = 1;
const OUT_BLOCK: usize = 2;

const FAIL_MARKERS: &[&str] = &[
    "failed to process outbound traffic",
    "failed to open connection",
    "i/o timeout",
    "connection refused",
    "connection reset",
    "no route to host",
    "handshake",
];

/// `tcp:host:port` / `udp:[v6]:port` -> (хост в нижнем регистре, порт).
fn split_target(token: &str) -> Option<(String, Option<u16>)> {
    let token = token.trim_matches(|c| c == '[' || c == ']' || c == ',' || c == '"');
    let rest = token
        .strip_prefix("tcp:")
        .or_else(|| token.strip_prefix("udp:"))?;
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (h, tail) = inner.split_once(']')?;
        (h, tail.strip_prefix(':').and_then(|p| p.parse().ok()))
    } else {
        match rest.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                (h, port.parse().ok())
            }
            _ => (rest, None),
        }
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some((host, port))
    }
}

enum Event {
    /// `[sid] proxy/tun: processing from ... to ...` — соединение пришло из TUN (а не от самого приложения).
    Tun,
    /// `[sid] app/dispatcher: sniffed domain: example.com`
    Sniffed,
    /// `[sid] app/dispatcher: taking detour [proxy] for [tcp:example.com:443]` — итоговый маршрут.
    Detour {
        out: usize,
        host: String,
        port: Option<u16>,
    },
    /// Любая другая строка сессии (нужна только для признака обрыва).
    Other,
}

struct ErrorLine {
    session: String,
    event: Event,
    failed: bool,
}

/// Строки error.log (уровень debug) несут и имя сайта, и маршрут, и номер сессии в скобках:
/// в access.log при TUN почти всегда только IP, поэтому берём всё отсюда.
fn parse_error(line: &str) -> Option<ErrorLine> {
    let mut session = None;
    let mut rest = line;
    while let Some(start) = rest.find('[') {
        let after = &rest[start + 1..];
        let Some(end) = after.find(']') else { break };
        let inner = &after[..end];
        if inner.len() >= 3 && inner.bytes().all(|b| b.is_ascii_digit()) {
            session = Some(inner.to_string());
            break;
        }
        rest = &after[end + 1..];
    }
    let session = session?;
    let event = if line.contains("proxy/tun: processing from") {
        Event::Tun
    } else if line.contains("sniffed domain:") {
        Event::Sniffed
    } else if let Some((_, tail)) = line.split_once("taking detour [") {
        let detour = tail.split_once(']').and_then(|(tag, after)| {
            let out = match tag {
                "proxy" => OUT_PROXY,
                "direct" => OUT_DIRECT,
                "block" => OUT_BLOCK,
                _ => return None,
            };
            let target = after.split_once(" for [")?.1.split(']').next()?;
            let (host, port) = split_target(target)?;
            Some(Event::Detour { out, host, port })
        });
        detour.unwrap_or(Event::Other)
    } else {
        Event::Other
    };
    let lower = line.to_ascii_lowercase();
    let failed = FAIL_MARKERS.iter().any(|m| lower.contains(m));
    Some(ErrorLine {
        session,
        event,
        failed,
    })
}

/// Новые байты журнала после позиции `pos` (до последнего перевода строки) и новая позиция.
fn read_new(path: &str, pos: u64) -> (String, u64) {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return (String::new(), pos);
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut start = if len >= pos { pos } else { 0 };
    if len - start > MAX_READ {
        start = len - MAX_READ;
    }
    if file.seek(SeekFrom::Start(start)).is_err() {
        return (String::new(), pos);
    }
    let mut bytes = Vec::new();
    if file.take(len - start).read_to_end(&mut bytes).is_err() {
        return (String::new(), pos);
    }
    // Недописанную последнюю строку оставляем на следующий опрос.
    let cut = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let text = String::from_utf8_lossy(&bytes[..cut]).into_owned();
    (text, start + cut as u64)
}

fn file_len(path: &str) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

// **********************************
// ИМЕНА: ГРУППИРОВКА, ЛОКАЛЬНЫЕ АДРЕСА
// **********************************
fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

fn is_local(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
    }
    !host.contains('.')
        || host.ends_with(".local")
        || host.ends_with(".lan")
        || host.ends_with(".internal")
        || host.ends_with(".home")
        || host.ends_with(".arpa")
}

fn ends_with_domain(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

/// Ключ группы, значение правила и признак «общий CDN».
fn group_of(host: &str) -> (String, String, bool, &'static str) {
    if is_ip(host) {
        return (host.to_string(), host.to_string(), false, "ip");
    }
    if SHARED_HOSTS.iter().any(|s| ends_with_domain(host, s)) {
        return (host.to_string(), format!("full:{}", host), true, "domain");
    }
    let labels: Vec<&str> = host.split('.').collect();
    let take = if labels.len() >= 3 && MULTI_SUFFIXES.iter().any(|s| ends_with_domain(host, s)) {
        3
    } else {
        2
    };
    let key = if labels.len() <= take {
        host.to_string()
    } else {
        labels[labels.len() - take..].join(".")
    };
    let rule = format!("domain:{}", key);
    (key, rule, false, "domain")
}

// **********************************
// ПРАВИЛА: СОВПАДЕНИЕ АДРЕСА С ПРАВИЛАМИ И С GEOSITE
// **********************************
#[derive(Default)]
struct Matcher {
    suffix: HashSet<String>,
    full: HashSet<String>,
    plain: Vec<String>,
    ips: HashSet<String>,
    cidrs: Vec<(u32, u32)>,
}

impl Matcher {
    fn add_domain(&mut self, kind: u8, value: &str) {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            return;
        }
        match kind {
            2 => {
                self.suffix.insert(value);
            }
            3 => {
                self.full.insert(value);
            }
            0 => self.plain.push(value),
            _ => {}
        }
    }

    fn add_ip(&mut self, value: &str) {
        let value = value.trim();
        if let Some((addr, bits)) = value.split_once('/') {
            if let (Ok(a), Ok(b)) = (addr.parse::<std::net::Ipv4Addr>(), bits.parse::<u32>()) {
                if b <= 32 {
                    let mask = if b == 0 { 0 } else { u32::MAX << (32 - b) };
                    self.cidrs.push((u32::from(a) & mask, mask));
                }
            }
        } else if !value.is_empty() {
            self.ips.insert(value.to_ascii_lowercase());
        }
    }

    fn matches(&self, host: &str) -> bool {
        if is_ip(host) {
            if self.ips.contains(host) {
                return true;
            }
            if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
                let n = u32::from(v4);
                return self.cidrs.iter().any(|(net, mask)| n & mask == *net);
            }
            return false;
        }
        if self.full.contains(host) || self.suffix.contains(host) {
            return true;
        }
        let mut rest = host;
        while let Some(i) = rest.find('.') {
            rest = &rest[i + 1..];
            if self.suffix.contains(rest) {
                return true;
            }
        }
        self.plain.iter().any(|p| host.contains(p.as_str()))
    }
}

struct GeoDomain {
    kind: u8,
    value: String,
    attrs: Vec<String>,
}

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

fn read_varint(buf: &[u8], i: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *buf.get(*i)?;
        *i += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

fn parse_fields(buf: &[u8]) -> Vec<(u32, Field<'_>)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        let Some(key) = read_varint(buf, &mut i) else {
            break;
        };
        let number = (key >> 3) as u32;
        match key & 7 {
            0 => {
                let Some(v) = read_varint(buf, &mut i) else {
                    break;
                };
                out.push((number, Field::Varint(v)));
            }
            1 => i += 8,
            2 => {
                let Some(len) = read_varint(buf, &mut i) else {
                    break;
                };
                let end = i.saturating_add(len as usize);
                if end > buf.len() {
                    break;
                }
                out.push((number, Field::Bytes(&buf[i..end])));
                i = end;
            }
            5 => i += 4,
            _ => break,
        }
    }
    out
}

/// Читает из geosite.dat только запрошенные теги (нижний регистр, без `@атрибута`).
fn load_geosite_tags(data: &[u8], wanted: &HashSet<String>) -> HashMap<String, Vec<GeoDomain>> {
    let mut result: HashMap<String, Vec<GeoDomain>> = HashMap::new();
    if wanted.is_empty() {
        return result;
    }
    for (number, field) in parse_fields(data) {
        let (1, Field::Bytes(entry)) = (number, field) else {
            continue;
        };
        let fields = parse_fields(entry);
        let code = fields.iter().find_map(|(n, f)| match (n, f) {
            (1, Field::Bytes(b)) => Some(String::from_utf8_lossy(b).to_ascii_lowercase()),
            _ => None,
        });
        let Some(code) = code else { continue };
        if !wanted.contains(&code) {
            continue;
        }
        let mut domains = Vec::new();
        for (n, f) in fields {
            let (2, Field::Bytes(raw)) = (n, f) else {
                continue;
            };
            let mut kind = 0u8;
            let mut value = String::new();
            let mut attrs = Vec::new();
            for (dn, df) in parse_fields(raw) {
                match (dn, df) {
                    (1, Field::Varint(v)) => kind = v as u8,
                    (2, Field::Bytes(b)) => value = String::from_utf8_lossy(b).into_owned(),
                    (3, Field::Bytes(b)) => {
                        for (an, af) in parse_fields(b) {
                            if let (1, Field::Bytes(k)) = (an, af) {
                                attrs.push(String::from_utf8_lossy(k).to_ascii_lowercase());
                            }
                        }
                    }
                    _ => {}
                }
            }
            domains.push(GeoDomain { kind, value, attrs });
        }
        result.insert(code, domains);
    }
    result
}

/// `geosite:google@ads` -> ("google", Some("ads"))
fn split_tag(raw: &str) -> (String, Option<String>) {
    let raw = raw
        .trim()
        .trim_start_matches("geosite:")
        .to_ascii_lowercase();
    match raw.split_once('@') {
        Some((tag, attr)) => (tag.to_string(), Some(attr.to_string())),
        None => (raw, None),
    }
}

fn add_geo_tag(
    matcher: &mut Matcher,
    geo: &HashMap<String, Vec<GeoDomain>>,
    tag: &str,
    attr: &Option<String>,
) {
    let Some(list) = geo.get(tag) else { return };
    for d in list {
        if let Some(a) = attr {
            if !d.attrs.iter().any(|x| x == a) {
                continue;
            }
        }
        matcher.add_domain(d.kind, &d.value);
    }
}

fn read_geosite() -> Option<Vec<u8>> {
    let path = GEOSITE_PATH
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| DEFAULT_GEOSITE_PATH.to_string());
    std::fs::read(path).ok()
}

/// Матчер правил пользователя (все три зоны). Для geosite-тегов нужен geosite.dat.
fn build_rules_matcher(rules: &Value, geo_data: Option<&[u8]>) -> Matcher {
    let mut matcher = Matcher::default();
    let mut tags: Vec<(String, Option<String>)> = Vec::new();
    for zone in ["direct", "proxy", "block"] {
        let Some(list) = rules.get(zone).and_then(|v| v.as_array()) else {
            continue;
        };
        for rule in list {
            let kind = rule.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let value = rule
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if value.is_empty() {
                continue;
            }
            match kind {
                "geosite" => tags.push(split_tag(value)),
                "ip" => matcher.add_ip(value),
                "keyword" => matcher.add_domain(0, value),
                "domain" => {
                    if let Some(v) = value.strip_prefix("domain:") {
                        matcher.add_domain(2, v);
                    } else if let Some(v) = value.strip_prefix("full:") {
                        matcher.add_domain(3, v);
                    } else if let Some(v) = value.strip_prefix("keyword:") {
                        matcher.add_domain(0, v);
                    } else if value.starts_with("regexp:") { /* регулярные выражения не вычисляем */
                    } else if value.starts_with("geosite:") {
                        tags.push(split_tag(value));
                    } else {
                        matcher.add_domain(0, value);
                    }
                }
                _ => {}
            }
        }
    }
    if let (Some(data), false) = (geo_data, tags.is_empty()) {
        let wanted: HashSet<String> = tags.iter().map(|(t, _)| t.clone()).collect();
        let geo = load_geosite_tags(data, &wanted);
        for (tag, attr) in &tags {
            add_geo_tag(&mut matcher, &geo, tag, attr);
        }
    }
    matcher
}

fn build_ads_matcher(geo_data: Option<&[u8]>) -> (Matcher, bool) {
    let mut matcher = Matcher::default();
    for host in BUILTIN_ADS {
        matcher.add_domain(2, host);
    }
    let mut loaded = false;
    if let Some(data) = geo_data {
        let wanted: HashSet<String> = [ADS_TAG.to_string()].into_iter().collect();
        let geo = load_geosite_tags(data, &wanted);
        loaded = geo.contains_key(ADS_TAG);
        add_geo_tag(&mut matcher, &geo, ADS_TAG, &None);
    }
    (matcher, loaded)
}

struct Matchers {
    ads: Arc<Matcher>,
    covered: Arc<Matcher>,
}

/// Матчеры кэшируются: опрос идёт раз в секунду, а geosite.dat — несколько мегабайт.
static ADS_CACHE: Mutex<Option<Arc<Matcher>>> = Mutex::new(None);
static RULES_CACHE: Mutex<Option<(String, Arc<Matcher>)>> = Mutex::new(None);

fn matchers_for(rules: &Value) -> Matchers {
    let mut geo: Option<Vec<u8>> = None;
    let ads = {
        let mut cache = ADS_CACHE.lock().unwrap();
        if let Some(m) = cache.as_ref() {
            m.clone()
        } else {
            geo = read_geosite();
            let (matcher, loaded) = build_ads_matcher(geo.as_deref());
            let arc = Arc::new(matcher);
            if loaded {
                *cache = Some(arc.clone());
            }
            arc
        }
    };
    let key = rules.to_string();
    let covered = {
        let mut cache = RULES_CACHE.lock().unwrap();
        match cache.as_ref() {
            Some((k, m)) if *k == key => m.clone(),
            _ => {
                if geo.is_none() {
                    geo = read_geosite();
                }
                let arc = Arc::new(build_rules_matcher(rules, geo.as_deref()));
                *cache = Some((key, arc.clone()));
                arc
            }
        }
    };
    Matchers { ads, covered }
}

// **********************************
// СЕССИЯ ПОИСКА
// **********************************
#[derive(Default)]
struct HostStat {
    out: [u32; 3],
    failed: u32,
    last_seen: Option<Instant>,
}

struct Session {
    direction: usize,
    error_path: String,
    error_pos: u64,
    hosts: HashMap<String, HostStat>,
    /// Сессии TUN: номер -> маршрутизированный хост (когда он уже известен).
    sessions: HashMap<String, Option<String>>,
    failed_sessions: HashSet<String>,
    background: HashSet<String>,
    bg_count: u32,
}

#[derive(Default)]
pub struct FinderState(Mutex<Option<Session>>);

impl FinderState {
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<Session>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub key: String,
    pub rule_type: String,
    pub rule_value: String,
    pub count: u32,
    pub failed: u32,
    pub shared: bool,
    pub hosts: Vec<String>,
    pub ago_secs: u64,
}

struct Classified {
    items: Vec<Item>,
    hidden_ads: u32,
    hidden_covered: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recent {
    pub key: String,
    pub ago_secs: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Сколько адресов ушло в «фон» (после отметки), либо сколько их сейчас, пока фон идёт.
    pub background: u32,
    pub count: u32,
    pub recent: Vec<Recent>,
    pub more: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub items: Vec<Item>,
    pub hidden_ads: u32,
    pub hidden_covered: u32,
}

impl Session {
    fn new(direction: usize, error_path: String) -> Session {
        let error_pos = file_len(&error_path);
        Session {
            direction,
            error_path,
            error_pos,
            hosts: HashMap::new(),
            sessions: HashMap::new(),
            failed_sessions: HashSet::new(),
            background: HashSet::new(),
            bg_count: 0,
        }
    }

    fn ingest(&mut self) {
        let (text, pos) = read_new(&self.error_path, self.error_pos);
        self.error_pos = pos;
        let now = Instant::now();
        for line in text.lines() {
            let Some(parsed) = parse_error(line) else {
                continue;
            };
            if self.sessions.len() >= MAX_SESSIONS {
                self.sessions.clear();
                self.failed_sessions.clear();
            }
            match parsed.event {
                Event::Tun => {
                    self.sessions.entry(parsed.session.clone()).or_insert(None);
                }
                Event::Detour { out, host, port } => {
                    // Только соединения из TUN; DNS (порт 53) не интересен.
                    if !self.sessions.contains_key(&parsed.session) || port == Some(53) {
                        continue;
                    }
                    if self.hosts.len() >= MAX_HOSTS && !self.hosts.contains_key(&host) {
                        continue;
                    }
                    let stat = self.hosts.entry(host.clone()).or_default();
                    stat.out[out] = stat.out[out].saturating_add(1);
                    stat.last_seen = Some(now);
                    self.sessions.insert(parsed.session.clone(), Some(host));
                }
                Event::Sniffed | Event::Other => {}
            }
            if parsed.failed {
                if let Some(Some(host)) = self.sessions.get(&parsed.session).cloned() {
                    if self.failed_sessions.insert(parsed.session) {
                        if let Some(stat) = self.hosts.get_mut(&host) {
                            stat.failed = stat.failed.saturating_add(1);
                        }
                    }
                }
            }
        }
    }

    fn classify(&self, m: &Matchers) -> Classified {
        let now = Instant::now();
        let mut groups: HashMap<String, Item> = HashMap::new();
        let (mut hidden_ads, mut hidden_covered) = (0u32, 0u32);
        for (host, stat) in &self.hosts {
            let count = stat.out[self.direction];
            if count == 0 || self.background.contains(host) || is_local(host) {
                continue;
            }
            if m.ads.matches(host) {
                hidden_ads += 1;
                continue;
            }
            if m.covered.matches(host) {
                hidden_covered += 1;
                continue;
            }
            let (key, rule_value, shared, rule_type) = group_of(host);
            let ago = stat
                .last_seen
                .map(|t| now.duration_since(t).as_secs())
                .unwrap_or(0);
            let item = groups.entry(key.clone()).or_insert_with(|| Item {
                key,
                rule_type: rule_type.to_string(),
                rule_value,
                count: 0,
                failed: 0,
                shared,
                hosts: Vec::new(),
                ago_secs: u64::MAX,
            });
            item.count = item.count.saturating_add(count);
            item.failed = item.failed.saturating_add(stat.failed);
            item.ago_secs = item.ago_secs.min(ago);
            if item.hosts.len() < 3 {
                item.hosts.push(host.clone());
            }
        }
        let mut items: Vec<Item> = groups.into_values().collect();
        for item in &mut items {
            item.hosts.sort();
        }
        // Сначала оборвавшиеся, потом обычные, общие CDN в конце; внутри — по числу обращений.
        items.sort_by(|a, b| {
            (b.failed > 0)
                .cmp(&(a.failed > 0))
                .then(a.shared.cmp(&b.shared))
                .then(b.count.cmp(&a.count))
                .then(a.key.cmp(&b.key))
        });
        Classified {
            items,
            hidden_ads,
            hidden_covered,
        }
    }
}

fn parse_direction(direction: &str) -> Result<usize, String> {
    match direction {
        "proxy" => Ok(OUT_PROXY),
        "direct" => Ok(OUT_DIRECT),
        _ => Err("direction".into()),
    }
}

// **********************************
// КОМАНДЫ
// **********************************
/// Начать поиск. `direction` — какие адреса смотрим: «proxy» (шли через VPN) или
/// «direct» (шли напрямую). Возвращает `true`, если ядро нужно переподключить, чтобы оно
/// начало писать журнал (Android).
#[tauri::command]
pub async fn finder_start(
    app: AppHandle,
    state: State<'_, FinderState>,
    direction: String,
) -> Result<bool, String> {
    let direction = parse_direction(&direction)?;
    #[cfg(target_os = "android")]
    {
        let dir = app.path().app_data_dir().map_err(|_| "log".to_string())?;
        let _ = std::fs::create_dir_all(&dir);
        let log = dir.join("finder-error.log");
        std::fs::write(&log, b"").map_err(|_| "log".to_string())?;
        let log = log.to_string_lossy().to_string();
        if let Ok(mut g) = GEOSITE_PATH.lock() {
            *g = Some(dir.join("geosite.dat").to_string_lossy().to_string());
        }
        set_log_override(Some(log.clone()));
        *state.slot() = Some(Session::new(direction, log));
        Ok(true)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = &app;
        let (err_path, _) = crate::get_log_paths();
        if !std::path::Path::new(&err_path).exists() {
            return Err("log".into());
        }
        *state.slot() = Some(Session::new(direction, err_path));
        Ok(false)
    }
}

/// Конец фона: всё, что видели до сих пор, больше не попадёт в список. Возвращает,
/// сколько подходящих адресов ушло в фон.
#[tauri::command]
pub async fn finder_mark_background(
    state: State<'_, FinderState>,
    rules: Value,
) -> Result<u32, String> {
    let m = matchers_for(&rules);
    let mut guard = state.slot();
    let session = guard.as_mut().ok_or("session")?;
    session.ingest();
    let relevant = session.classify(&m).items.len() as u32;
    let hosts: Vec<String> = session.hosts.keys().cloned().collect();
    session.background.extend(hosts);
    session.bg_count = relevant;
    Ok(relevant)
}

/// Короткая сводка для экрана поиска.
#[tauri::command]
pub async fn finder_poll(state: State<'_, FinderState>, rules: Value) -> Result<Snapshot, String> {
    let m = matchers_for(&rules);
    let mut guard = state.slot();
    let session = guard.as_mut().ok_or("session")?;
    session.ingest();
    let classified = session.classify(&m);
    let mut recent: Vec<&Item> = classified.items.iter().collect();
    recent.sort_by_key(|i| i.ago_secs);
    let count = classified.items.len() as u32;
    Ok(Snapshot {
        background: if session.background.is_empty() {
            count
        } else {
            session.bg_count
        },
        count,
        recent: recent
            .iter()
            .take(3)
            .map(|i| Recent {
                key: i.key.clone(),
                ago_secs: i.ago_secs,
            })
            .collect(),
        more: count.saturating_sub(3),
    })
}

#[tauri::command]
pub async fn finder_result(state: State<'_, FinderState>, rules: Value) -> Result<Outcome, String> {
    let m = matchers_for(&rules);
    let mut guard = state.slot();
    let session = guard.as_mut().ok_or("session")?;
    session.ingest();
    let c = session.classify(&m);
    Ok(Outcome {
        items: c.items,
        hidden_ads: c.hidden_ads,
        hidden_covered: c.hidden_covered,
    })
}

/// Стереть всё найденное из памяти и журнал. Возвращает `true`, если ядро нужно
/// переподключить, чтобы вернуть обычный режим журнала (Android).
#[tauri::command]
pub async fn finder_stop(state: State<'_, FinderState>) -> Result<bool, String> {
    let path = state.slot().take().map(|s| s.error_path);
    let restore = log_override().is_some();
    set_log_override(None);
    if restore {
        if let Some(p) = path {
            let _ = std::fs::remove_file(p);
        }
    }
    Ok(restore)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn bytes_field(number: u32, data: &[u8]) -> Vec<u8> {
        let mut out = varint(((number as u64) << 3) | 2);
        out.extend(varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    fn domain(kind: u64, value: &str, attr: Option<&str>) -> Vec<u8> {
        let mut d = varint(8);
        d.extend(varint(kind));
        d.extend(bytes_field(2, value.as_bytes()));
        if let Some(a) = attr {
            d.extend(bytes_field(3, &bytes_field(1, a.as_bytes())));
        }
        d
    }

    fn site(code: &str, domains: Vec<Vec<u8>>) -> Vec<u8> {
        let mut body = bytes_field(1, code.as_bytes());
        for d in domains {
            body.extend(bytes_field(2, &d));
        }
        bytes_field(1, &body)
    }

    fn geo_fixture() -> Vec<u8> {
        let mut data = site(
            "CATEGORY-ADS-ALL",
            vec![
                domain(2, "adserver.test", None),
                domain(3, "px.example.org", None),
            ],
        );
        data.extend(site(
            "RU-LIKE",
            vec![
                domain(2, "yandex.ru", None),
                domain(2, "tracker.yandex.ru", Some("ads")),
            ],
        ));
        data
    }

    // Реальные строки из error.log Xray (уровень debug), присланные пользователем.
    const L_TUN: &str = "2026/10/20 17:38:09.238587 [Info] [63787514] proxy/tun: processing from tcp:172.19.0.2:38304 to tcp:178.253.6.178:443";
    const L_SNIFF: &str = "2026/10/20 17:38:09.240103 [Info] [63787514] app/dispatcher: sniffed domain: maruwlkzoh.top";
    const L_DETOUR: &str = "2026/10/20 17:38:09.240228 [Info] [63787514] app/dispatcher: taking detour [proxy] for [tcp:maruwlkzoh.top:443]";

    #[test]
    fn real_error_log_lines_are_parsed() {
        assert!(matches!(parse_error(L_TUN).unwrap().event, Event::Tun));
        assert!(matches!(
            parse_error(L_SNIFF).unwrap().event,
            Event::Sniffed
        ));
        let e = parse_error(L_DETOUR).unwrap();
        assert_eq!(e.session, "63787514");
        match e.event {
            Event::Detour { out, host, port } => {
                assert_eq!(
                    (out, host.as_str(), port),
                    (OUT_PROXY, "maruwlkzoh.top", Some(443))
                );
            }
            _ => panic!("detour expected"),
        }
        // DNS-маршруты и строки без сессии не считаются маршрутом сайта
        let dns = parse_error("2026/10/20 17:38:09.136412 [Info] [665337853] app/dispatcher: taking detour [dns-out] for [udp:1.1.1.1:53]").unwrap();
        assert!(matches!(dns.event, Event::Other));
        assert!(parse_error("2026/10/20 17:38:09.136706 [Info] app/dispatcher: taking detour [direct] for [tcp:dns.yandex.ru:443]").is_none());
        let fail = parse_error("2026/10/20 17:38:10 [Info] [63787514] proxy/vless/outbound: failed to process outbound traffic > i/o timeout").unwrap();
        assert!(fail.failed);
        let v6 = split_target("tcp:[2001:db8::1]:443").unwrap();
        assert_eq!((v6.0.as_str(), v6.1), ("2001:db8::1", Some(443)));
    }

    #[test]
    fn grouping_and_shared_hosts() {
        assert_eq!(group_of("cdn.video.example.com").0, "example.com");
        assert_eq!(group_of("a.b.example.co.uk").0, "example.co.uk");
        assert_eq!(group_of("user.github.io").0, "user.github.io");
        let shared = group_of("d111.cloudfront.net");
        assert!(shared.2);
        assert_eq!(shared.0, "d111.cloudfront.net");
        assert_eq!(shared.1, "full:d111.cloudfront.net");
        let ip = group_of("1.2.3.4");
        assert_eq!((ip.1.as_str(), ip.3), ("1.2.3.4", "ip"));
        assert_eq!(group_of("example.com").1, "domain:example.com");
    }

    #[test]
    fn local_hosts_are_skipped() {
        for h in [
            "localhost",
            "192.168.1.5",
            "10.0.0.1",
            "printer.local",
            "172.19.0.2",
            "::1",
        ] {
            assert!(is_local(h), "{}", h);
        }
        for h in ["example.com", "8.8.8.8"] {
            assert!(!is_local(h), "{}", h);
        }
    }

    #[test]
    fn geosite_tags_and_attributes() {
        let data = geo_fixture();
        let wanted: HashSet<String> = ["category-ads-all".to_string(), "ru-like".to_string()]
            .into_iter()
            .collect();
        let geo = load_geosite_tags(&data, &wanted);
        assert_eq!(geo["category-ads-all"].len(), 2);
        assert_eq!(geo["ru-like"][1].attrs, vec!["ads".to_string()]);
        let (ads, loaded) = build_ads_matcher(Some(&data));
        assert!(loaded);
        assert!(ads.matches("x.adserver.test"));
        assert!(ads.matches("px.example.org"));
        assert!(!ads.matches("other.example.org"));
        assert!(ads.matches("stats.doubleclick.net"));
    }

    #[test]
    fn rules_matcher_covers_all_rule_kinds() {
        let data = geo_fixture();
        let rules = json!({
            "direct": [ {"type":"geosite","value":"ru-like"}, {"type":"domain","value":"domain:covered.test"} ],
            "proxy": [ {"type":"domain","value":"full:exact.test"}, {"type":"keyword","value":"stream"}, {"type":"ip","value":"203.0.113.0/24"}, {"type":"domain","value":"plain.test"} ],
            "block": [ {"type":"domain","value":"regexp:.*\\.never$"} ]
        });
        let m = build_rules_matcher(&rules, Some(&data));
        assert!(m.matches("www.yandex.ru"));
        assert!(m.matches("a.covered.test"));
        assert!(m.matches("exact.test") && !m.matches("sub.exact.test"));
        assert!(m.matches("live-stream.example.com"));
        assert!(m.matches("203.0.113.9") && !m.matches("203.0.114.9"));
        assert!(m.matches("xplain.testy.com"));
        assert!(!m.matches("example.com"));
        // без geosite.dat теги просто не срабатывают, ошибки нет
        assert!(!build_rules_matcher(&rules, None).matches("www.yandex.ru"));
    }

    #[test]
    fn session_end_to_end() {
        let dir = std::env::temp_dir().join(format!("karin-finder-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = dir.join("error.log").to_string_lossy().into_owned();
        std::fs::write(&err, "[Info] [1111] proxy/tun: processing from a to b\n[Info] [1111] app/dispatcher: taking detour [proxy] for [tcp:old.test:443]\n").unwrap();
        let mut s = Session::new(OUT_PROXY, err.clone());
        let sess = |id: &str, host: &str, tag: &str, port: u16| {
            format!(
            "t [Info] [{id}] proxy/tun: processing from tcp:172.19.0.2:1 to tcp:9.9.9.9:{port}\nt [Info] [{id}] app/dispatcher: sniffed domain: {host}\nt [Info] [{id}] app/dispatcher: taking detour [{tag}] for [tcp:{host}:{port}]\n")
        };
        let mut log = String::new();
        log.push_str(&sess("2001", "www.site.test", "proxy", 443));
        log.push_str(&sess("2002", "cdn.site.test", "direct", 443));
        // сессия приложения (не из TUN) и DNS-трафик не считаются
        log.push_str("t [Info] [2003] app/dispatcher: taking detour [proxy] for [tcp:cp.cloudflare.com:80]\n");
        log.push_str(&sess("2004", "dns.google", "proxy", 53));
        std::fs::write(&err, format!("[Info] [1111] proxy/tun: processing from a to b\n[Info] [1111] app/dispatcher: taking detour [proxy] for [tcp:old.test:443]\n{}", log)).unwrap();
        let m = Matchers {
            ads: Arc::new(build_ads_matcher(None).0),
            covered: Arc::new(build_rules_matcher(
                &json!({"direct":[{"type":"domain","value":"domain:covered.test"}]}),
                None,
            )),
        };
        s.ingest();
        assert!(
            !s.hosts.contains_key("old.test"),
            "строки до старта не видны"
        );
        assert!(!s.hosts.contains_key("cp.cloudflare.com") && !s.hosts.contains_key("dns.google"));
        s.background.extend(s.hosts.keys().cloned());
        let mut more = String::new();
        more.push_str(&sess("3001", "video.live.test", "proxy", 443));
        more.push_str(&sess("3002", "video.live.test", "proxy", 443));
        more.push_str(&sess("3003", "api.live.test", "proxy", 443));
        more.push_str(&sess("3004", "d9.cloudfront.net", "proxy", 443));
        more.push_str(&sess("3005", "x.covered.test", "proxy", 443));
        more.push_str(&sess("3006", "mc.yandex.ru", "proxy", 443));
        more.push_str("t [Info] [3001] proxy/vless/outbound: failed to process outbound traffic > i/o timeout\n");
        more.push_str("t [Info] [3001] proxy/vless/outbound: connection reset\n");
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&err)
            .unwrap()
            .write_all(more.as_bytes())
            .unwrap();
        s.ingest();
        let c = s.classify(&m);
        assert_eq!(c.items.len(), 2, "{:?}", c.items);
        assert_eq!(c.items[0].key, "live.test");
        assert_eq!(c.items[0].count, 3);
        assert_eq!(c.items[0].failed, 1, "одна сессия считается один раз");
        assert_eq!(c.items[0].rule_value, "domain:live.test");
        assert!(c.items[1].shared);
        assert_eq!((c.hidden_ads, c.hidden_covered), (1, 1));
        std::fs::remove_dir_all(&dir).ok();
    }
}
