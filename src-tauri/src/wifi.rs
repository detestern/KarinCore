//! Wi‑Fi сети через NetworkManager (`nmcli`): текущая сеть, видимые сети и сохранённые.
//!
//! Только стандартная библиотека. Разбор вывода вынесен в чистые функции, чтобы его
//! можно было проверить тестами без NetworkManager.

use std::io::ErrorKind;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub ssid: String,
    /// Уровень сигнала 0..=100 (0 для сохранённой сети, которой сейчас не видно).
    pub signal: u8,
    pub secure: bool,
    /// Компьютер подключён к этой сети сейчас.
    pub in_use: bool,
    /// Сеть сохранена в NetworkManager.
    pub known: bool,
}

/// Делит строку терс-режима nmcli (`-t`) по неэкранированным двоеточиям.
/// Внутри значений `:` записано как `\:`, а обратная косая черта как `\\`.
pub fn split_terse(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(next) => current.push(next),
                None => current.push('\\'),
            },
            ':' => fields.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    fields.push(current);
    fields
}

/// Разбирает `nmcli -t -f IN-USE,SSID,SIGNAL,SECURITY dev wifi list`.
/// Одна сеть может вещаться с нескольких точек доступа: оставляем сильнейший сигнал.
/// Скрытые сети (пустое имя) пропускаются.
pub fn parse_wifi_list(output: &str) -> Vec<Network> {
    let mut networks: Vec<Network> = Vec::new();
    for line in output.lines() {
        let fields = split_terse(line);
        if fields.len() < 4 {
            continue;
        }
        let ssid = fields[1].trim().to_string();
        if ssid.is_empty() {
            continue;
        }
        let in_use = fields[0].trim() == "*";
        let signal = fields[2].trim().parse::<u8>().unwrap_or(0).min(100);
        let secure = !fields[3].trim().is_empty() && fields[3].trim() != "--";
        match networks.iter_mut().find(|n| n.ssid == ssid) {
            Some(existing) => {
                existing.in_use |= in_use;
                existing.signal = existing.signal.max(signal);
                existing.secure |= secure;
            }
            None => networks.push(Network { ssid, signal, secure, in_use, known: false }),
        }
    }
    networks
}

/// Имена сохранённых Wi‑Fi подключений из `nmcli -t -f NAME,TYPE connection show`.
pub fn parse_known_wifi(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let fields = split_terse(line);
            if fields.len() < 2 {
                return None;
            }
            let kind = fields[1].trim();
            let name = fields[0].trim();
            if (kind == "802-11-wireless" || kind == "wifi") && !name.is_empty() {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Объединяет видимые и сохранённые сети. Порядок: текущая, затем по силе сигнала,
/// затем сохранённые, которых сейчас не видно (по алфавиту).
pub fn merge_networks(mut visible: Vec<Network>, known: &[String]) -> Vec<Network> {
    for network in visible.iter_mut() {
        if known.contains(&network.ssid) {
            network.known = true;
        }
    }
    let mut missing: Vec<&String> = known.iter().filter(|k| !visible.iter().any(|n| n.ssid == **k)).collect();
    missing.sort();
    missing.dedup();
    visible.sort_by(|a, b| b.in_use.cmp(&a.in_use).then(b.signal.cmp(&a.signal)).then(a.ssid.cmp(&b.ssid)));
    for ssid in missing {
        visible.push(Network { ssid: ssid.clone(), signal: 0, secure: true, in_use: false, known: true });
    }
    visible
}

/// Имя сети, к которой компьютер подключён сейчас.
pub fn current_ssid(networks: &[Network]) -> Option<String> {
    networks.iter().find(|n| n.in_use).map(|n| n.ssid.clone())
}

fn run_nmcli(args: &[&str]) -> Result<String, String> {
    match Command::new("nmcli").args(args).output() {
        Ok(out) if out.status.success() => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        Ok(_) => Err("nmcli failed".to_string()),
        Err(e) if e.kind() == ErrorKind::NotFound => Err("nmcli not found".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Видимые сети (из кэша сканирования, без запроса прав) и сохранённые.
pub fn read_networks() -> Result<Vec<Network>, String> {
    let list = run_nmcli(&["-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "no"])?;
    let known = run_nmcli(&["-t", "-f", "NAME,TYPE", "connection", "show"]).map(|o| parse_known_wifi(&o)).unwrap_or_default();
    Ok(merge_networks(parse_wifi_list(&list), &known))
}

/// Только текущая сеть: дешевле, чем полный список. Вызывается по таймеру.
pub fn read_current_ssid() -> Result<Option<String>, String> {
    let list = run_nmcli(&["-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "no"])?;
    Ok(current_ssid(&parse_wifi_list(&list)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_handles_escaped_colons_and_backslashes() {
        assert_eq!(split_terse(r"*:My\:Net:78:WPA2"), vec!["*", "My:Net", "78", "WPA2"]);
        assert_eq!(split_terse(r"a\\b:c"), vec![r"a\b", "c"]);
        assert_eq!(split_terse(""), vec![""]);
        assert_eq!(split_terse("x\\"), vec!["x\\"]);
    }

    #[test]
    fn wifi_list_parses_dedupes_and_skips_hidden() {
        let out = " :Home-5G:70:WPA2\n*:Home-5G:90:WPA2\n :Cafe Guest:45:\n :  :30:WPA2\n :Metro:20:--\n:broken\n";
        let nets = parse_wifi_list(out);
        assert_eq!(nets.len(), 3);
        let home = nets.iter().find(|n| n.ssid == "Home-5G").unwrap();
        assert!(home.in_use);
        assert_eq!(home.signal, 90);
        assert!(home.secure);
        let cafe = nets.iter().find(|n| n.ssid == "Cafe Guest").unwrap();
        assert!(!cafe.secure && !cafe.in_use);
        let metro = nets.iter().find(|n| n.ssid == "Metro").unwrap();
        assert!(!metro.secure);
    }

    #[test]
    fn signal_is_clamped_and_garbage_is_zero() {
        let nets = parse_wifi_list(" :A:250:WPA2\n :B:abc:WPA2\n");
        assert_eq!(nets[0].signal, 100);
        assert_eq!(nets[1].signal, 0);
    }

    #[test]
    fn known_connections_keep_only_wifi() {
        let out = "Home-5G:802-11-wireless\nWired connection 1:802-3-ethernet\nCafe:wifi\nvpn0:wireguard\nTP\\:Link:802-11-wireless\n";
        assert_eq!(parse_known_wifi(out), vec!["Home-5G", "Cafe", "TP:Link"]);
    }

    #[test]
    fn merge_orders_current_then_signal_then_missing_known() {
        let visible = parse_wifi_list(" :Weak:20:WPA2\n*:Home:60:WPA2\n :Strong:95:WPA2\n");
        let known = vec!["Home".to_string(), "Dacha".to_string(), "Weak".to_string(), "Dacha".to_string()];
        let merged = merge_networks(visible, &known);
        let names: Vec<&str> = merged.iter().map(|n| n.ssid.as_str()).collect();
        assert_eq!(names, vec!["Home", "Strong", "Weak", "Dacha"]);
        assert!(merged[0].known && !merged[1].known && merged[2].known);
        assert!(merged[3].known && merged[3].signal == 0 && !merged[3].in_use);
    }

    #[test]
    fn current_ssid_is_the_one_in_use() {
        let nets = parse_wifi_list(" :A:80:WPA2\n*:B:50:WPA2\n");
        assert_eq!(current_ssid(&nets), Some("B".to_string()));
        assert_eq!(current_ssid(&parse_wifi_list(" :A:80:WPA2\n")), None);
        assert_eq!(current_ssid(&[]), None);
    }
}
