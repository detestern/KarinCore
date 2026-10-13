//! Протокол запроса к helper'у (stdin).
//!
//!   KARIN-HELPER/1 <op> [key=value ...]\n
//!   <ровно body_len байт тела>
//!
//! Никакого JSON и shell: операция — слово из фиксированного списка, параметры —
//! `key=value` с жёстко ограниченным алфавитом значений, тело — «сырые» байты
//! (конфигурация), максимальный размер которых зависит от операции.

use std::io::Read;

pub const MAGIC: &str = "KARIN-HELPER/1";
pub const MAX_HEADER: usize = 4096;

pub struct Request {
    pub op: String,
    pub params: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// Максимальный размер тела для операции; `None` — операция неизвестна.
pub fn max_body(op: &str) -> Option<usize> {
    Some(match op {
        "core-config" => 1024 * 1024,
        "ovpn-start" => 256 * 1024,
        "wg-up" => 64 * 1024,
        "geo-install" => 64 * 1024 * 1024,
        "version" | "core-restart" | "core-stop" | "ovpn-stop" | "wg-down" | "wg-status-log" | "route-fwmark"
        | "route-cleanup" | "bypass" | "ks-on" | "ks-off" | "dns-vpn" | "dns-restore" | "logs-clear" | "teardown"
        | "stop-services" => 0,
        _ => return None,
    })
}

fn valid_op(op: &str) -> bool {
    !op.is_empty() && op.len() <= 24 && op.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
}

fn valid_key(k: &str) -> bool {
    !k.is_empty() && k.len() <= 24 && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

fn valid_value(v: &str) -> bool {
    v.len() <= 1024
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b',' | b'/' | b'+' | b'=' | b'-'))
}

/// Разбирает заголовок (без `\n`). Возвращает (op, params, body_len).
type Header = (String, Vec<(String, String)>, usize);

pub fn parse_header(line: &str) -> Result<Header, String> {
    let mut it = line.split(' ');
    if it.next() != Some(MAGIC) {
        return Err("неверная версия протокола helper'а".into());
    }
    let op = it.next().ok_or("не указана операция")?.to_string();
    if !valid_op(&op) {
        return Err("недопустимое имя операции".into());
    }
    let mut params: Vec<(String, String)> = Vec::new();
    let mut body_len = 0usize;
    for tok in it {
        let (k, v) = tok.split_once('=').ok_or("параметр должен иметь вид key=value")?;
        if !valid_key(k) || !valid_value(v) {
            return Err("недопустимый параметр".into());
        }
        if params.iter().any(|(pk, _)| pk == k) || (k == "body_len" && body_len != 0) {
            return Err("повторяющийся параметр".into());
        }
        if k == "body_len" {
            body_len = v.parse::<usize>().map_err(|_| "body_len должен быть числом".to_string())?;
        }
        params.push((k.to_string(), v.to_string()));
    }
    Ok((op, params, body_len))
}

/// Читает запрос целиком. Заголовок читается побайтно до `\n`, чтобы не
/// «съесть» тело.
pub fn read_request<R: Read>(r: &mut R) -> Result<Request, String> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => return Err("неожиданный конец запроса".into()),
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                header.push(byte[0]);
                if header.len() > MAX_HEADER {
                    return Err("слишком длинный заголовок запроса".into());
                }
            }
            Err(e) => return Err(format!("ошибка чтения запроса: {}", e)),
        }
    }
    let line = String::from_utf8(header).map_err(|_| "заголовок запроса не UTF-8".to_string())?;
    let (op, params, body_len) = parse_header(&line)?;
    let limit = max_body(&op).ok_or_else(|| format!("неизвестная операция: {}", op))?;
    if body_len > limit {
        return Err(format!("тело запроса слишком большое для операции {}", op));
    }
    let mut body = vec![0u8; body_len];
    r.read_exact(&mut body).map_err(|_| "тело запроса короче, чем заявлено".to_string())?;
    // после тела не должно быть лишнего
    let mut extra = [0u8; 1];
    if r.read(&mut extra).map(|n| n != 0).unwrap_or(false) {
        return Err("после тела запроса есть лишние данные".into());
    }
    Ok(Request { op, params, body })
}

#[cfg(test)]
pub fn encode_header(op: &str, params: &[(&str, &str)], body_len: usize) -> String {
    let mut s = format!("{} {}", MAGIC, op);
    for (k, v) in params {
        s.push_str(&format!(" {}={}", k, v));
    }
    if body_len > 0 {
        s.push_str(&format!(" body_len={}", body_len));
    }
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(bytes: &[u8]) -> Result<Request, String> {
        read_request(&mut &bytes[..])
    }

    #[test]
    fn parses_simple_op() {
        let r = req(b"KARIN-HELPER/1 ks-on server_ip=203.0.113.5 iface=tun0\n").unwrap();
        assert_eq!(r.op, "ks-on");
        assert_eq!(r.param("server_ip"), Some("203.0.113.5"));
        assert_eq!(r.param("iface"), Some("tun0"));
        assert!(r.body.is_empty());
    }

    #[test]
    fn parses_body_exactly() {
        let r = req(b"KARIN-HELPER/1 core-config body_len=5\nhello").unwrap();
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn body_shorter_or_longer_rejected() {
        assert!(req(b"KARIN-HELPER/1 core-config body_len=10\nhello").is_err());
        assert!(req(b"KARIN-HELPER/1 core-config body_len=2\nhello").is_err());
    }

    #[test]
    fn body_limit_per_op() {
        assert!(req(b"KARIN-HELPER/1 ks-off body_len=1\nx").is_err());
        let big = format!("KARIN-HELPER/1 wg-up body_len={}\n", 64 * 1024 + 1);
        assert!(req(big.as_bytes()).is_err());
    }

    #[test]
    fn unknown_op_and_bad_magic() {
        assert!(req(b"KARIN-HELPER/1 rm-rf\n").is_err());
        assert!(req(b"KARIN-HELPER/2 ks-off\n").is_err());
        assert!(req(b"hello\n").is_err());
        assert!(req(b"").is_err());
    }

    #[test]
    fn hostile_params_rejected() {
        for bad in [
            "KARIN-HELPER/1 ks-on server_ip=1.2.3.4;id\n",
            "KARIN-HELPER/1 ks-on server_ip=$(id)\n",
            "KARIN-HELPER/1 ks-on server_ip=a\"b\n",
            "KARIN-HELPER/1 ks-on SERVER=1\n",
            "KARIN-HELPER/1 ks-on iface\n",
            "KARIN-HELPER/1 ks-on a=1 a=2\n",
            "KARIN-HELPER/1 ks-on a=1\\n\n",
            "KARIN-HELPER/1 ks-on a=\u{442}\n",
            "KARIN-HELPER/1  ks-on\n",
        ] {
            assert!(req(bad.as_bytes()).is_err(), "{:?}", bad);
        }
    }

    #[test]
    fn header_length_limit() {
        let long = format!("KARIN-HELPER/1 ks-on x={}\n", "a".repeat(MAX_HEADER));
        assert!(req(long.as_bytes()).is_err());
    }

    #[test]
    fn encode_roundtrip() {
        let h = encode_header("ks-on", &[("server_ip", "1.2.3.4"), ("iface", "wg0")], 0);
        let r = req(h.as_bytes()).unwrap();
        assert_eq!(r.op, "ks-on");
        let h2 = encode_header("wg-up", &[], 3);
        let mut data = h2.into_bytes();
        data.extend_from_slice(b"abc");
        let r2 = req(&data).unwrap();
        assert_eq!(r2.body, b"abc");
    }

    #[test]
    fn trailing_garbage_after_body_rejected() {
        assert!(req(b"KARIN-HELPER/1 ks-off\nextra").is_err());
    }
}
