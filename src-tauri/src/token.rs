//! Токен локального прокси (пароль для inbound'ов на 127.0.0.1).
//!
//! Раньше токен строился из текущего времени в наносекундах — это предсказуемо.
//! Теперь 256 бит берутся из CSPRNG системы: `/dev/urandom` на Linux,
//! `ProcessPrng` на Windows (тот же источник использует стандартная библиотека Rust).

use std::io::Read;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn generate_from<R: Read>(src: &mut R) -> Result<String, String> {
    let mut buf = [0u8; 32];
    src.read_exact(&mut buf)
        .map_err(|e| format!("Не удалось получить случайные данные для токена: {}", e))?;
    Ok(format!("karin_{}", to_hex(&buf)))
}

#[cfg(not(windows))]
pub fn generate() -> Result<String, String> {
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("Не удалось открыть /dev/urandom: {}", e))?;
    generate_from(&mut f)
}

#[cfg(windows)]
pub fn generate() -> Result<String, String> {
    generate_from(&mut WinRng)
}

/// Системный CSPRNG Windows (bcryptprimitives.dll, Windows 10 и новее).
/// По документации `ProcessPrng` всегда возвращает TRUE и заполняет буфер целиком.
#[cfg(windows)]
struct WinRng;

#[cfg(windows)]
#[link(name = "bcryptprimitives", kind = "raw-dylib")]
extern "system" {
    fn ProcessPrng(pbdata: *mut u8, cbdata: usize) -> i32;
}

#[cfg(windows)]
impl Read for WinRng {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: указатель и длина берутся из одного живого буфера `buf`.
        if unsafe { ProcessPrng(buf.as_mut_ptr(), buf.len()) } == 0 {
            return Err(std::io::Error::other("ProcessPrng failed"));
        }
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_has_256_bits_of_hex() {
        let t = generate().unwrap();
        let hex = t.strip_prefix("karin_").unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn tokens_differ() {
        assert_ne!(generate().unwrap(), generate().unwrap());
    }

    #[test]
    fn token_is_not_derived_from_time() {
        // два токена подряд не должны иметь общего длинного префикса (у времени он был бы)
        let a = generate().unwrap();
        let b = generate().unwrap();
        let common = a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count();
        assert!(common < "karin_".len() + 8);
    }

    #[test]
    fn short_source_is_an_error() {
        let mut short: &[u8] = &[1, 2, 3];
        assert!(generate_from(&mut short).is_err());
    }

    #[test]
    fn known_bytes_encode_as_hex() {
        let mut src: &[u8] = &[0xab; 32];
        assert_eq!(generate_from(&mut src).unwrap(), format!("karin_{}", "ab".repeat(32)));
    }
}
