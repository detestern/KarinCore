//! Вердикт диагностики: чистая логика без сети и без внешних зависимостей.
//!
//! Сетевые пробы (DNS, TCP, запрос через туннель) выполняются командами в main.rs
//! и приходят сюда короткими строками. Здесь они сводятся к одному коду причины
//! и состоянию пяти шагов, которые интерфейс показывает пользователю.

/// Порог, после которого рабочий туннель считается медленным.
pub const SLOW_TUNNEL_MS: u64 = 800;

/// Сколько последних строк журнала Xray берём в разбор и показываем в «Подробностях».
pub const LOG_EXCERPT_LINES: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Ok,
    Failed,
    Skipped,
}

impl Step {
    pub fn as_str(self) -> &'static str {
        match self {
            Step::Ok => "ok",
            Step::Failed => "failed",
            Step::Skipped => "skipped",
        }
    }
}

/// Результаты проб в том виде, в каком их отдают команды.
pub struct Inputs<'a> {
    /// Туннель сейчас поднят (кнопка «Отключить» на главном экране).
    pub vpn_on: bool,
    /// "tcp" — VLESS/VMess/Trojan/SS, "other" — OpenVPN/WireGuard, "none" — сервер не выбран.
    pub transport: &'a str,
    /// "ok" | "fail"
    pub internet: &'a str,
    /// "ok" | "fail" | "na" (адрес сервера уже IP)
    pub dns: &'a str,
    /// "open" | "refused" | "timeout" | "unreachable" | "na"
    pub tcp: &'a str,
    /// "ok" | "fail" | "na" (запрос через туннель не выполнялся)
    pub tunnel: &'a str,
    pub tunnel_ms: u64,
    /// Строки журнала Xray, появившиеся во время запроса через туннель.
    pub tunnel_log: &'a [String],
    /// "yes" | "no" | "na"
    pub core: &'a str,
    pub kill_switch: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Код причины: по нему интерфейс берёт текст и кнопку.
    pub code: &'static str,
    /// Уточнение к коду: например, "refused" / "timeout" для недоступного сервера.
    pub detail: &'static str,
    /// Интернет, DNS, порт сервера, рукопожатие, запрос через туннель.
    pub steps: [Step; 5],
}

/// Признаки того, что сервер ответил, но не принял ключи или параметры подключения.
const HANDSHAKE_MARKERS: [&str; 10] = [
    "reality",
    "invalid user",
    "invalid request",
    "authentication failed",
    "bad certificate",
    "certificate",
    "tls: ",
    "handshake",
    "x509",
    "unknown user",
];

/// Журнал Xray указывает на отказ в рукопожатии (ключ, сертификат, пользователь).
pub fn log_shows_handshake_failure(lines: &[String]) -> bool {
    lines.iter().any(|line| {
        let lower = line.to_lowercase();
        HANDSHAKE_MARKERS
            .iter()
            .any(|marker| lower.contains(marker))
    })
}

/// Оставляет последние `LOG_EXCERPT_LINES` непустых строк.
pub fn tail_lines(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty())
        .collect();
    let start = lines.len().saturating_sub(LOG_EXCERPT_LINES);
    lines[start..].iter().map(|l| l.to_string()).collect()
}

/// Строки журнала, появившиеся после снимка `before`. Если журнал успел обрезаться
/// или пересоздаться (начало не совпало), берём хвост всего журнала.
pub fn new_log_lines(before: &str, after: &str) -> Vec<String> {
    match after.strip_prefix(before) {
        Some(added) => tail_lines(added),
        None => tail_lines(after),
    }
}

fn outcome(code: &'static str, detail: &'static str, steps: [Step; 5]) -> Outcome {
    Outcome {
        code,
        detail,
        steps,
    }
}

pub fn verdict(i: &Inputs) -> Outcome {
    use Step::{Failed as F, Ok as O, Skipped as S};

    if i.transport == "none" {
        return outcome("no_server", "", [S, S, S, S, S]);
    }

    // Пока туннель поднят, «интернет» и порт сервера могут идти через сам туннель.
    // Если порт сервера открылся, сеть точно есть, даже когда проба интернета не прошла.
    let tcp_open = i.tcp == "open";
    let internet_ok = i.internet == "ok" || tcp_open;
    if !internet_ok {
        return outcome("no_internet", "", [F, S, S, S, S]);
    }

    if i.dns == "fail" {
        return outcome("dns_fail", "", [O, F, S, S, S]);
    }

    let has_port_step = i.transport == "tcp";
    if has_port_step {
        match i.tcp {
            "refused" => return outcome("server_unreachable", "refused", [O, O, F, S, S]),
            "timeout" => return outcome("server_unreachable", "timeout", [O, O, F, S, S]),
            "unreachable" => return outcome("server_unreachable", "unreachable", [O, O, F, S, S]),
            _ => {}
        }
    }
    let port_step = if has_port_step { O } else { S };

    if !i.vpn_on {
        return outcome("vpn_off", "", [O, O, port_step, S, S]);
    }

    if i.core == "no" {
        let code = if i.kill_switch {
            "killswitch_blocking"
        } else {
            "core_stopped"
        };
        return outcome(code, "", [O, O, port_step, S, S]);
    }

    if i.tunnel == "ok" {
        let handshake = if has_port_step { O } else { S };
        let code = if i.tunnel_ms > SLOW_TUNNEL_MS {
            "slow"
        } else {
            "ok"
        };
        return outcome(code, "", [O, O, port_step, handshake, O]);
    }

    if i.tunnel == "fail" {
        if has_port_step && log_shows_handshake_failure(i.tunnel_log) {
            return outcome("handshake_rejected", "", [O, O, port_step, F, S]);
        }
        let handshake = if has_port_step { O } else { S };
        if i.kill_switch && i.tcp != "open" && has_port_step {
            return outcome("killswitch_blocking", "", [O, O, port_step, S, S]);
        }
        return outcome("tunnel_no_traffic", "", [O, O, port_step, handshake, F]);
    }

    // Запрос через туннель не выполнялся, хотя туннель поднят: считаем, что проверять нечего.
    outcome("vpn_off", "", [O, O, port_step, S, S])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base<'a>(log: &'a [String]) -> Inputs<'a> {
        Inputs {
            vpn_on: true,
            transport: "tcp",
            internet: "ok",
            dns: "ok",
            tcp: "open",
            tunnel: "ok",
            tunnel_ms: 84,
            tunnel_log: log,
            core: "yes",
            kill_switch: false,
        }
    }

    #[test]
    fn healthy_tunnel_is_ok() {
        let log = vec![];
        let v = verdict(&base(&log));
        assert_eq!(v.code, "ok");
        assert_eq!(v.steps, [Step::Ok; 5]);
    }

    #[test]
    fn slow_tunnel_is_flagged() {
        let log = vec![];
        let mut i = base(&log);
        i.tunnel_ms = SLOW_TUNNEL_MS + 1;
        assert_eq!(verdict(&i).code, "slow");
        i.tunnel_ms = SLOW_TUNNEL_MS;
        assert_eq!(verdict(&i).code, "ok");
    }

    #[test]
    fn no_server_skips_everything() {
        let log = vec![];
        let mut i = base(&log);
        i.transport = "none";
        let v = verdict(&i);
        assert_eq!(v.code, "no_server");
        assert_eq!(v.steps, [Step::Skipped; 5]);
    }

    #[test]
    fn no_internet_stops_at_first_step() {
        let log = vec![];
        let mut i = base(&log);
        i.vpn_on = false;
        i.internet = "fail";
        i.tcp = "timeout";
        i.tunnel = "na";
        let v = verdict(&i);
        assert_eq!(v.code, "no_internet");
        assert_eq!(
            v.steps,
            [
                Step::Failed,
                Step::Skipped,
                Step::Skipped,
                Step::Skipped,
                Step::Skipped
            ]
        );
    }

    #[test]
    fn open_server_port_proves_internet_even_if_probe_failed() {
        let log = vec![];
        let mut i = base(&log);
        i.internet = "fail";
        assert_eq!(verdict(&i).code, "ok");
    }

    #[test]
    fn dns_failure_reported() {
        let log = vec![];
        let mut i = base(&log);
        i.vpn_on = false;
        i.dns = "fail";
        i.tcp = "unreachable";
        i.tunnel = "na";
        let v = verdict(&i);
        assert_eq!(v.code, "dns_fail");
        assert_eq!(v.steps[1], Step::Failed);
    }

    #[test]
    fn server_port_failures_keep_their_detail() {
        let log = vec![];
        for (tcp, detail) in [
            ("refused", "refused"),
            ("timeout", "timeout"),
            ("unreachable", "unreachable"),
        ] {
            let mut i = base(&log);
            i.vpn_on = false;
            i.tcp = tcp;
            i.tunnel = "na";
            let v = verdict(&i);
            assert_eq!(v.code, "server_unreachable");
            assert_eq!(v.detail, detail);
            assert_eq!(
                v.steps,
                [
                    Step::Ok,
                    Step::Ok,
                    Step::Failed,
                    Step::Skipped,
                    Step::Skipped
                ]
            );
        }
    }

    #[test]
    fn vpn_off_checks_only_the_network_and_server() {
        let log = vec![];
        let mut i = base(&log);
        i.vpn_on = false;
        i.tunnel = "na";
        let v = verdict(&i);
        assert_eq!(v.code, "vpn_off");
        assert_eq!(
            v.steps,
            [Step::Ok, Step::Ok, Step::Ok, Step::Skipped, Step::Skipped]
        );
    }

    #[test]
    fn handshake_rejection_is_read_from_the_xray_log() {
        let log = vec![
            "2026/10/16 14:00:01 [Info] app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic".to_string(),
            "2026/10/16 14:00:01 REALITY: processed invalid connection".to_string(),
        ];
        let mut i = base(&log);
        i.tunnel = "fail";
        let v = verdict(&i);
        assert_eq!(v.code, "handshake_rejected");
        assert_eq!(
            v.steps,
            [Step::Ok, Step::Ok, Step::Ok, Step::Failed, Step::Skipped]
        );
    }

    #[test]
    fn failed_tunnel_without_handshake_signs_is_no_traffic() {
        let log =
            vec!["2026/10/16 14:00:01 [Info] proxy/vless/outbound: tunneling request".to_string()];
        let mut i = base(&log);
        i.tunnel = "fail";
        let v = verdict(&i);
        assert_eq!(v.code, "tunnel_no_traffic");
        assert_eq!(
            v.steps,
            [Step::Ok, Step::Ok, Step::Ok, Step::Ok, Step::Failed]
        );
    }

    #[test]
    fn stopped_core_is_reported_unless_kill_switch_explains_it() {
        let log = vec![];
        let mut i = base(&log);
        i.core = "no";
        i.tunnel = "na";
        assert_eq!(verdict(&i).code, "core_stopped");
        i.kill_switch = true;
        assert_eq!(verdict(&i).code, "killswitch_blocking");
    }

    #[test]
    fn kill_switch_with_closed_server_port_and_dead_tunnel_is_blocking() {
        let log = vec![];
        let mut i = base(&log);
        i.tunnel = "fail";
        i.tcp = "na";
        i.internet = "ok";
        i.kill_switch = true;
        assert_eq!(verdict(&i).code, "killswitch_blocking");
    }

    #[test]
    fn openvpn_and_wireguard_skip_port_and_handshake_steps() {
        let log = vec![];
        let mut i = base(&log);
        i.transport = "other";
        i.tcp = "na";
        i.dns = "na";
        let v = verdict(&i);
        assert_eq!(v.code, "ok");
        assert_eq!(
            v.steps,
            [Step::Ok, Step::Ok, Step::Skipped, Step::Skipped, Step::Ok]
        );
        i.tunnel = "fail";
        let v = verdict(&i);
        assert_eq!(v.code, "tunnel_no_traffic");
        assert_eq!(v.steps[2], Step::Skipped);
    }

    #[test]
    fn new_log_lines_returns_only_what_was_appended() {
        let before = "a\nb\n";
        let after = "a\nb\nc\nd\n";
        assert_eq!(
            new_log_lines(before, after),
            vec!["c".to_string(), "d".to_string()]
        );
        assert!(new_log_lines(after, after).is_empty());
    }

    #[test]
    fn new_log_lines_falls_back_to_the_tail_when_the_log_was_rotated() {
        let lines = new_log_lines("old line 1\nold line 2\n", "fresh 1\nfresh 2\n");
        assert_eq!(lines, vec!["fresh 1".to_string(), "fresh 2".to_string()]);
    }

    #[test]
    fn tail_lines_keeps_the_end_and_drops_blanks() {
        let mut text = String::new();
        for n in 0..100 {
            text.push_str(&format!("line {}\n\n", n));
        }
        let tail = tail_lines(&text);
        assert_eq!(tail.len(), LOG_EXCERPT_LINES);
        assert_eq!(tail.last().map(String::as_str), Some("line 99"));
        assert_eq!(tail[0], "line 60");
    }
}
