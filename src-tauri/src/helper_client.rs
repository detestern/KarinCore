//! Клиент к привилегированному helper'у (`karincore-helper`).
//!
//! Раньше GUI вызывал `sudo cp`, `sudo openvpn`, `sudo iptables …` и т. д., а
//! sudoers разрешал всё это любому участнику группы `karincore`. Теперь
//! sudoers разрешает один бинарник без аргументов, а запрос уходит ему в stdin
//! (протокол описан в `helper/proto.rs`). Проверка параметров и конфигураций
//! выполняется на стороне root, а не здесь.
//!
//! На Windows тот же протокол уходит службе KarinCore через named pipe (`helper_pipe.rs`).

use std::io::Write;
use std::process::{Command, Stdio};

#[cfg_attr(windows, allow(dead_code))]
pub const HELPER_PATH: &str = "/usr/libexec/karincore/karincore-helper";
const MAGIC: &str = "KARIN-HELPER/1";

fn encode_header(op: &str, params: &[(&str, &str)], body_len: usize) -> String {
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

/// Ответ helper'а (или службы на Windows): первая строка `OK` или `ERR`, дальше сообщение.
/// `None` — ответ не в этом формате.
fn parse_reply(stdout: &str) -> Option<Result<String, String>> {
    let mut lines = stdout.splitn(2, '\n');
    let first = lines.next().unwrap_or("").trim_end();
    let rest = lines.next().unwrap_or("").trim_end().to_string();
    match first {
        "OK" => Some(Ok(rest)),
        "ERR" => Some(Err(if rest.is_empty() { "helper вернул ошибку".to_string() } else { rest })),
        _ => None,
    }
}

/// Любой ответ не в формате helper'а — это ошибка самого sudo (нет прав, не установлен helper).
#[cfg_attr(windows, allow(dead_code))]
fn parse_response(stdout: &str, stderr: &str) -> Result<String, String> {
    parse_reply(stdout).unwrap_or_else(|| Err(sudo_failure_message(stderr)))
}

#[cfg_attr(windows, allow(dead_code))]
fn sudo_failure_message(stderr: &str) -> String {
    let s = stderr.trim();
    let hint = "Нет доступа к helper'у KarinCore. Убедитесь, что пакет установлен целиком, а ваш пользователь состоит в группе karincore \
                (sudo gpasswd -a $USER karincore), после чего перезайдите в сессию.";
    if s.is_empty() {
        hint.to_string()
    } else {
        format!("{}\n({})", hint, s)
    }
}

#[cfg_attr(windows, allow(dead_code))]
fn run_command(mut cmd: Command, op: &str, params: &[(&str, &str)], body: Option<&[u8]>) -> Result<String, String> {
    let body_len = body.map(|b| b.len()).unwrap_or(0);
    let header = encode_header(op, params, body_len);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Не удалось запустить helper: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        // Если helper отверг запрос раньше, чем мы дописали тело, получим BrokenPipe —
        // это не ошибка: причина будет в его ответе.
        let _ = stdin.write_all(header.as_bytes());
        if let Some(b) = body {
            let _ = stdin.write_all(b);
        }
    }
    let out = child.wait_with_output().map_err(|e| format!("Ошибка ожидания helper'а: {}", e))?;
    parse_response(&String::from_utf8_lossy(&out.stdout), &String::from_utf8_lossy(&out.stderr))
}

/// Вызов операции helper'а через `sudo -n`.
#[cfg(not(windows))]
pub fn call(op: &str, params: &[(&str, &str)], body: Option<&[u8]>) -> Result<String, String> {
    let mut cmd = Command::new("sudo");
    cmd.args(["-n", HELPER_PATH]);
    run_command(cmd, op, params, body)
}

/// Операции, ради которых службу стоит запустить. Остальные (остановка, очистка)
/// при незапущенной службе делать нечего: ядра нет, отвечаем «готово».
#[cfg(windows)]
const OPS_THAT_START_THE_SERVICE: &[&str] = &["version", "core-config", "core-restart"];

/// Вызов операции службы KarinCore через named pipe.
#[cfg(windows)]
pub fn call(op: &str, params: &[(&str, &str)], body: Option<&[u8]>) -> Result<String, String> {
    let body_len = body.map(|b| b.len()).unwrap_or(0);
    let mut message = encode_header(op, params, body_len).into_bytes();
    if let Some(b) = body {
        message.extend_from_slice(b);
    }
    let Some(out) = crate::helper_pipe::transact(&message, OPS_THAT_START_THE_SERVICE.contains(&op))? else {
        return Ok(String::new());
    };
    parse_reply(&String::from_utf8_lossy(&out))
        .unwrap_or_else(|| Err("Служба KarinCore ответила в неизвестном формате. Переустановите KarinCore.".into()))
}

/// Вызов, результат которого не важен (очистка, остановка).
pub fn call_quiet(op: &str, params: &[(&str, &str)]) {
    let _ = call(op, params, None);
}

// Тесты запускают `sh` и проверяют Linux-транспорт через sudo.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.arg("-c").arg(script);
        c
    }

    #[test]
    fn header_encoding() {
        assert_eq!(encode_header("ks-off", &[], 0), "KARIN-HELPER/1 ks-off\n");
        assert_eq!(
            encode_header("ks-on", &[("server_ip", "1.2.3.4"), ("iface", "tun0")], 0),
            "KARIN-HELPER/1 ks-on server_ip=1.2.3.4 iface=tun0\n"
        );
        assert_eq!(encode_header("core-config", &[], 5), "KARIN-HELPER/1 core-config body_len=5\n");
    }

    #[test]
    fn ok_and_err_responses() {
        assert_eq!(parse_response("OK\n", ""), Ok(String::new()));
        assert_eq!(parse_response("OK\npid=42\n", ""), Ok("pid=42".to_string()));
        assert_eq!(parse_response("ERR\nплохой конфиг\n", ""), Err("плохой конфиг".to_string()));
        assert_eq!(parse_response("ERR\n", ""), Err("helper вернул ошибку".to_string()));
    }

    #[test]
    fn sudo_failure_gets_actionable_message() {
        let e = parse_response("", "sudo: a password is required").unwrap_err();
        assert!(e.contains("karincore"));
        assert!(e.contains("a password is required"));
        let e2 = parse_response("", "").unwrap_err();
        assert!(e2.contains("gpasswd"));
    }

    #[test]
    fn request_and_body_reach_the_process() {
        let r = run_command(sh("printf 'OK\\n'; cat"), "core-config", &[], Some(b"hello")).unwrap();
        assert!(r.contains("KARIN-HELPER/1 core-config body_len=5"));
        assert!(r.ends_with("hello"));
    }

    #[test]
    fn helper_rejecting_early_does_not_hang_or_error_on_big_body() {
        let big = vec![b'x'; 8 * 1024 * 1024];
        let r = run_command(sh("printf 'ERR\\nнет\\n'; exit 1"), "geo-install", &[("name", "geoip")], Some(&big));
        assert_eq!(r, Err("нет".to_string()));
    }

    #[test]
    fn missing_binary_is_reported() {
        let r = run_command(Command::new("/nonexistent/helper"), "version", &[], None);
        assert!(r.unwrap_err().contains("Не удалось запустить helper"));
    }
}
