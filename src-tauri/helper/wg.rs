//! Фильтр конфигурации WireGuard (формат wg-quick): allowlist ключей.
//!
//! `wg-quick up` исполняет `PreUp`/`PostUp`/`PreDown`/`PostDown` через shell от
//! root. Пропускаем только ключи, нужные для туннеля, и пересобираем файл
//! сами; `Table = off` и `FwMark = 255` добавляет helper (политика маршрутизации
//! KarinCore), `DNS` вычёркивается — DNS подменяется отдельным шагом.

pub struct Filtered {
    pub text: String,
    pub dropped: Vec<String>,
}

#[derive(PartialEq, Clone, Copy)]
enum Section {
    None,
    Interface,
    Peer,
}

fn is_b64_key(v: &str) -> bool {
    v.len() == 44
        && v.ends_with('=')
        && v[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn is_ip_cidr_list(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 512
        && v.split(',').all(|part| {
            let p = part.trim();
            if p.is_empty() {
                return false;
            }
            let (addr, mask) = match p.split_once('/') {
                Some((a, m)) => (a, Some(m)),
                None => (p, None),
            };
            let ip = match addr.parse::<std::net::IpAddr>() {
                Ok(ip) => ip,
                Err(_) => return false,
            };
            // Длина префикса зависит от семейства: IPv4 до 32, IPv6 до 128.
            let max = if ip.is_ipv4() { 32 } else { 128 };
            match mask {
                None => true,
                Some(m) => m.parse::<u8>().map(|n| n <= max).unwrap_or(false),
            }
        })
}

fn is_number_in(v: &str, lo: u32, hi: u32) -> bool {
    v.parse::<u32>().map(|n| n >= lo && n <= hi).unwrap_or(false)
}

fn is_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':' || b == b'_')
}

/// Возвращает (host, port) для `host:port` или `[v6]:port`.
fn split_endpoint(v: &str) -> Option<(String, u32)> {
    let (host, port) = if let Some(rest) = v.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (h.to_string(), p)
    } else {
        let (h, p) = v.rsplit_once(':')?;
        if h.contains(':') {
            return None; // IPv6 без скобок — неоднозначно
        }
        (h.to_string(), p)
    };
    let port = port.parse::<u32>().ok()?;
    if port == 0 || port > 65535 || !is_host(&host) {
        return None;
    }
    Some((host, port))
}

pub fn filter(raw: &str) -> Result<Filtered, String> {
    if raw.contains('\0') {
        return Err("Конфигурация WireGuard содержит нулевой байт".into());
    }
    let mut dropped: Vec<String> = Vec::new();
    let note = |name: &str, d: &mut Vec<String>| {
        let n: String = name.chars().take(40).collect();
        if !d.contains(&n) {
            d.push(n);
        }
    };

    // Собираем структуру, затем печатаем в каноническом порядке.
    struct Iface {
        private_key: Option<String>,
        address: Option<String>,
        mtu: Option<String>,
        listen_port: Option<String>,
    }
    #[derive(Default)]
    struct Peer {
        public_key: Option<String>,
        preshared: Option<String>,
        allowed: Option<String>,
        endpoint: Option<String>,
        keepalive: Option<String>,
    }
    let mut iface = Iface { private_key: None, address: None, mtu: None, listen_port: None };
    let mut seen_iface = false;
    let mut peers: Vec<Peer> = Vec::new();
    let mut section = Section::None;

    for line in raw.lines() {
        // wg-quick отрезает всё после '#'
        let stripped = line.split('#').next().unwrap_or("").trim();
        if stripped.is_empty() {
            continue;
        }
        if stripped.starts_with('[') {
            match stripped.to_ascii_lowercase().as_str() {
                "[interface]" => {
                    if seen_iface {
                        return Err("В конфигурации WireGuard несколько секций [Interface]".into());
                    }
                    seen_iface = true;
                    section = Section::Interface;
                }
                "[peer]" => {
                    peers.push(Peer::default());
                    section = Section::Peer;
                }
                other => {
                    note(other, &mut dropped);
                    section = Section::None;
                }
            }
            continue;
        }
        let (key, value) = match stripped.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => {
                note(stripped, &mut dropped);
                continue;
            }
        };
        let lk = key.to_ascii_lowercase();
        match (section, lk.as_str()) {
            (Section::Interface, "privatekey") if is_b64_key(value) => iface.private_key = Some(value.into()),
            (Section::Interface, "address") if is_ip_cidr_list(value) => iface.address = Some(value.into()),
            (Section::Interface, "mtu") if is_number_in(value, 576, 9000) => iface.mtu = Some(value.into()),
            (Section::Interface, "listenport") if is_number_in(value, 1, 65535) => iface.listen_port = Some(value.into()),
            (Section::Peer, "publickey") if is_b64_key(value) => peers.last_mut().unwrap().public_key = Some(value.into()),
            (Section::Peer, "presharedkey") if is_b64_key(value) => peers.last_mut().unwrap().preshared = Some(value.into()),
            (Section::Peer, "allowedips") if is_ip_cidr_list(value) => peers.last_mut().unwrap().allowed = Some(value.into()),
            (Section::Peer, "endpoint") => match split_endpoint(value) {
                Some(_) => peers.last_mut().unwrap().endpoint = Some(value.into()),
                None => note(&lk, &mut dropped),
            },
            (Section::Peer, "persistentkeepalive") if is_number_in(value, 0, 65535) => {
                peers.last_mut().unwrap().keepalive = Some(value.into())
            }
            _ => note(&lk, &mut dropped),
        }
    }

    let private_key = iface
        .private_key
        .ok_or_else(|| "В конфигурации WireGuard нет корректного PrivateKey".to_string())?;
    if peers.is_empty() {
        return Err("В конфигурации WireGuard нет ни одной секции [Peer]".into());
    }

    let mut out = String::new();
    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", private_key));
    if let Some(a) = iface.address {
        out.push_str(&format!("Address = {}\n", a));
    }
    if let Some(m) = iface.mtu {
        out.push_str(&format!("MTU = {}\n", m));
    }
    if let Some(p) = iface.listen_port {
        out.push_str(&format!("ListenPort = {}\n", p));
    }
    out.push_str("Table = off\nFwMark = 255\n");
    for p in peers {
        let pk = p
            .public_key
            .ok_or_else(|| "В секции [Peer] нет корректного PublicKey".to_string())?;
        out.push_str("\n[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", pk));
        if let Some(v) = p.preshared {
            out.push_str(&format!("PresharedKey = {}\n", v));
        }
        if let Some(v) = p.allowed {
            out.push_str(&format!("AllowedIPs = {}\n", v));
        }
        if let Some(v) = p.endpoint {
            out.push_str(&format!("Endpoint = {}\n", v));
        }
        if let Some(v) = p.keepalive {
            out.push_str(&format!("PersistentKeepalive = {}\n", v));
        }
    }
    Ok(Filtered { text: out, dropped })
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const K2: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

    fn sample() -> String {
        format!(
            "[Interface]\nPrivateKey = {k1}\nAddress = 10.0.0.2/32, fd00::2/128\nDNS = 1.1.1.1\nMTU = 1380\n\n[Peer]\nPublicKey = {k2}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example.com:51820\nPersistentKeepalive = 25\n",
            k1 = K1,
            k2 = K2
        )
    }

    #[test]
    fn cidr_prefix_depends_on_address_family() {
        assert!(is_ip_cidr_list("10.0.0.2/32"));
        assert!(is_ip_cidr_list("0.0.0.0/0, ::/0"));
        assert!(is_ip_cidr_list("fd00::2/128"));
        assert!(is_ip_cidr_list("10.0.0.2"));
        assert!(!is_ip_cidr_list("10.0.0.2/33"));
        assert!(!is_ip_cidr_list("10.0.0.2/64"));
        assert!(!is_ip_cidr_list("fd00::2/129"));
        assert!(!is_ip_cidr_list("10.0.0.2/32, fd00::2/200"));
        assert!(!is_ip_cidr_list("10.0.0.2/"));
    }

    #[test]
    fn typical_config() {
        let f = filter(&sample()).unwrap();
        assert!(f.text.contains(&format!("PrivateKey = {}", K1)));
        assert!(f.text.contains("Address = 10.0.0.2/32, fd00::2/128"));
        assert!(f.text.contains("Endpoint = vpn.example.com:51820"));
        assert!(f.text.contains("Table = off\nFwMark = 255\n"));
        assert!(!f.text.contains("DNS"));
        assert!(f.dropped.contains(&"dns".to_string()));
    }

    #[test]
    fn hooks_are_dropped() {
        let cfg = sample().replace(
            "MTU = 1380",
            "PreUp = touch /tmp/a\nPostUp = id > /tmp/b\nPreDown = x\nPostDown = y\nSaveConfig = true",
        );
        let f = filter(&cfg).unwrap();
        for bad in ["PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig", "/tmp/"] {
            assert!(!f.text.contains(bad), "{}", bad);
        }
    }

    #[test]
    fn case_and_whitespace_tricks() {
        let cfg = sample().replace("MTU = 1380", "  postup   =   id\nPOSTUP=id\nPost Up = id\npostdown=id");
        let f = filter(&cfg).unwrap();
        assert!(!f.text.to_ascii_lowercase().contains("postup"));
        assert!(!f.text.to_ascii_lowercase().contains("postdown"));
        assert!(!f.text.contains("id\n"));
    }

    #[test]
    fn user_table_and_fwmark_are_replaced() {
        let cfg = sample().replace("MTU = 1380", "Table = 123\nFwMark = 5\nTable=main");
        let f = filter(&cfg).unwrap();
        assert_eq!(f.text.matches("Table").count(), 1);
        assert_eq!(f.text.matches("FwMark").count(), 1);
        assert!(f.text.contains("Table = off"));
        assert!(f.text.contains("FwMark = 255"));
    }

    #[test]
    fn comment_after_value_cannot_hide_hook() {
        let cfg = sample().replace("MTU = 1380", "MTU = 1380 # PostUp = id");
        let f = filter(&cfg).unwrap();
        assert!(!f.text.contains("PostUp"));
        assert!(f.text.contains("MTU = 1380"));
    }

    #[test]
    fn invalid_values_are_dropped_not_passed() {
        let cfg = sample()
            .replace("Address = 10.0.0.2/32, fd00::2/128", "Address = 10.0.0.2/32; id")
            .replace("MTU = 1380", "MTU = abc");
        let f = filter(&cfg).unwrap();
        assert!(!f.text.contains("Address"));
        assert!(!f.text.contains("MTU"));
        assert!(!f.text.contains("id"));
    }

    #[test]
    fn requires_private_key_and_peer() {
        assert!(filter("[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n").is_err());
        assert!(filter(&format!("[Interface]\nPrivateKey = {}\n", K1)).is_err());
        assert!(filter(&format!("[Interface]\nPrivateKey = {}\n[Peer]\nAllowedIPs = 0.0.0.0/0\n", K1)).is_err());
    }

    #[test]
    fn multiple_interfaces_rejected() {
        let cfg = format!("{}\n[Interface]\nPrivateKey = {}\n", sample(), K2);
        assert!(filter(&cfg).is_err());
    }

    #[test]
    fn multiple_peers_kept() {
        let cfg = format!("{}\n[Peer]\nPublicKey = {}\nAllowedIPs = 10.9.0.0/16\nEndpoint = [2001:db8::1]:51820\n", sample(), K1);
        let f = filter(&cfg).unwrap();
        assert_eq!(f.text.matches("[Peer]").count(), 2);
        assert!(f.text.contains("Endpoint = [2001:db8::1]:51820"));
    }

    #[test]
    fn bad_endpoint_dropped() {
        let cfg = sample().replace("vpn.example.com:51820", "vpn.example.com;id:51820");
        let f = filter(&cfg).unwrap();
        assert!(!f.text.contains("Endpoint"));
    }

    #[test]
    fn unknown_sections_are_ignored_with_their_keys() {
        let cfg = format!("{}\n[Foo]\nPostUp = id\nPublicKey = {}\n", sample(), K1);
        let f = filter(&cfg).unwrap();
        assert!(!f.text.contains("PostUp"));
        assert_eq!(f.text.matches("[Peer]").count(), 1);
    }

    #[test]
    fn nul_rejected() {
        assert!(filter("[Interface]\0\n").is_err());
    }
}
