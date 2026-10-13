//! Минимальный строгий JSON-парсер/сериализатор без внешних зависимостей.
//!
//! Helper работает от root, поэтому конфиг Xray, пришедший от GUI, нельзя
//! просто «проверить и скопировать»: между парсером проверки и парсером Go в
//! Xray могли бы быть расхождения (дубликаты ключей и т. п.). Мы разбираем
//! JSON сами, отвергаем всё неоднозначное и записываем на диск
//! **собственную каноническую сериализацию** — то, что проверено, и то, что
//! прочитает Xray, это один и тот же текст.

use std::fmt::Write as _;

pub const MAX_DEPTH: usize = 24;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Число хранится как исходный токен (уже проверенный по грамматике JSON),
    /// чтобы не терять точность и не менять формат.
    Num(String),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Obj(o) => Some(o),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_obj()?.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    /// Целое число без знака, если токен — обычное неотрицательное целое.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Num(n) if n.bytes().all(|b| b.is_ascii_digit()) => n.parse().ok(),
            _ => None,
        }
    }
}

pub fn parse(input: &str) -> Result<Value, String> {
    let mut p = Parser { s: input.as_bytes(), i: 0 };
    p.skip_ws();
    let v = p.value(0)?;
    p.skip_ws();
    if p.i != p.s.len() {
        return Err(format!("лишние данные после JSON (позиция {})", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, lit: &str) -> Result<(), String> {
        if self.s[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(format!("ожидалось '{}' (позиция {})", lit, self.i))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err("слишком глубокая вложенность JSON".into());
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.expect("true").map(|_| Value::Bool(true)),
            Some(b'f') => self.expect("false").map(|_| Value::Bool(false)),
            Some(b'n') => self.expect("null").map(|_| Value::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            _ => Err(format!("неожиданный символ (позиция {})", self.i)),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, String> {
        self.i += 1; // {
        let mut out: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Obj(out));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("ожидался ключ объекта (позиция {})", self.i));
            }
            let key = self.string()?;
            if out.iter().any(|(k, _)| *k == key) {
                return Err(format!("повторяющийся ключ '{}'", key));
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("ожидалось ':' (позиция {})", self.i));
            }
            self.i += 1;
            self.skip_ws();
            let v = self.value(depth + 1)?;
            out.push((key, v));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Obj(out));
                }
                _ => return Err(format!("ожидалось ',' или '}}' (позиция {})", self.i)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, String> {
        self.i += 1; // [
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Arr(out));
        }
        loop {
            self.skip_ws();
            out.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Arr(out));
                }
                _ => return Err(format!("ожидалось ',' или ']' (позиция {})", self.i)),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.s.len() {
            return Err("оборванная \\u-последовательность".into());
        }
        let mut v = 0u32;
        for k in 0..4 {
            let d = (self.s[self.i + k] as char)
                .to_digit(16)
                .ok_or_else(|| "некорректная \\u-последовательность".to_string())?;
            v = v * 16 + d;
        }
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // открывающая кавычка
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = self.peek().ok_or_else(|| "незакрытая строка".to_string())?;
            self.i += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or_else(|| "оборванный escape".to_string())?;
                    self.i += 1;
                    let ch: char = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                if self.s[self.i..].starts_with(b"\\u") {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return Err("некорректная суррогатная пара".into());
                                    }
                                    let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                    char::from_u32(cp).ok_or_else(|| "некорректный code point".to_string())?
                                } else {
                                    return Err("одиночный суррогат".into());
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err("одиночный суррогат".into());
                            } else {
                                char::from_u32(hi).ok_or_else(|| "некорректный code point".to_string())?
                            }
                        }
                        _ => return Err("неизвестная escape-последовательность".into()),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0x00..=0x1f => return Err("управляющий символ внутри строки".into()),
                _ => out.push(b),
            }
        }
        String::from_utf8(out).map_err(|_| "строка не является корректным UTF-8".to_string())
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(format!("некорректное число (позиция {})", start)),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            let d0 = self.i;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
            if self.i == d0 {
                return Err(format!("некорректное число (позиция {})", start));
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            let d0 = self.i;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
            if self.i == d0 {
                return Err(format!("некорректное число (позиция {})", start));
            }
        }
        Ok(Value::Num(String::from_utf8_lossy(&self.s[start..self.i]).into_owned()))
    }
}

/// Каноническая компактная сериализация.
pub fn to_string(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Num(n) => out.push_str(n),
        Value::Str(s) => write_str(s, out),
        Value::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(x, out);
            }
            out.push(']');
        }
        Value::Obj(o) => {
            out.push('{');
            for (i, (k, x)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(k, out);
                out.push(':');
                write_value(x, out);
            }
            out.push('}');
        }
    }
}

pub fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let src = r#"{"a":1,"b":[true,false,null,"x\ny"],"c":{"d":-1.5e3}}"#;
        let v = parse(src).unwrap();
        assert_eq!(to_string(&v), src);
        assert_eq!(v.get("a").and_then(|x| x.as_u64()), Some(1));
    }

    #[test]
    fn whitespace_is_normalised() {
        let v = parse(" { \"a\" : [ 1 , 2 ] } ").unwrap();
        assert_eq!(to_string(&v), r#"{"a":[1,2]}"#);
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert!(parse(r#"{"a":1,"a":2}"#).is_err());
    }

    #[test]
    fn rejects_trailing_garbage_and_commas() {
        assert!(parse(r#"{"a":1} x"#).is_err());
        assert!(parse(r#"{"a":1,}"#).is_err());
        assert!(parse(r#"[1,2,]"#).is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn rejects_bad_numbers() {
        for bad in ["01", "1.", ".5", "-", "1e", "+1", "0x10"] {
            assert!(parse(bad).is_err(), "{}", bad);
        }
        assert!(parse("0").is_ok());
        assert!(parse("-0.5E+2").is_ok());
    }

    #[test]
    fn control_chars_in_strings_rejected() {
        assert!(parse("\"a\nb\"").is_err());
        assert!(parse("\"a\u{1}b\"").is_err());
    }

    #[test]
    fn unicode_escapes_and_surrogates() {
        let v = parse(r#""A😀""#).unwrap();
        assert_eq!(v.as_str(), Some("A😀"));
        assert!(parse(r#""\ud83d""#).is_err());
        assert!(parse(r#""\ude00""#).is_err());
        assert!(parse(r#""\ud83dA""#).is_err());
    }

    #[test]
    fn serialisation_escapes_control_chars() {
        let v = Value::Str("a\u{1}\"b\\".to_string());
        assert_eq!(to_string(&v), "\"a\\u0001\\\"b\\\\\"");
        assert_eq!(parse(&to_string(&v)).unwrap(), v);
    }

    #[test]
    fn depth_limit() {
        let deep = "[".repeat(MAX_DEPTH + 5) + &"]".repeat(MAX_DEPTH + 5);
        assert!(parse(&deep).is_err());
        let ok = "[".repeat(5) + &"]".repeat(5);
        assert!(parse(&ok).is_ok());
    }

    #[test]
    fn invalid_utf8_escape_forms() {
        assert!(parse(r#""\x41""#).is_err());
        assert!(parse(r#""\u12""#).is_err());
    }
}
