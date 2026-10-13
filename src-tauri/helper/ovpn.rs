//! Фильтр конфигурации OpenVPN: allowlist директив.
//!
//! OpenVPN исполняет команды из конфигурации (`up`, `plugin`, `tls-verify`,
//! `auth-user-pass-verify`, …) с правами процесса, а процесс запускается от
//! root. Раньше GUI вычёркивал известные опасные директивы, но граница
//! привилегий проходила в GUI, а не на стороне root. Теперь helper сам
//! пропускает только известные безопасные директивы и пересобирает файл в
//! нормализованном виде; всё остальное отбрасывается и попадает в список
//! `dropped`, который показывается пользователю.
//!
//! Директивы, читающие файлы по пути (`ca`, `cert`, `key`, `tls-auth`,
//! `auth-user-pass <file>`, …), тоже не разрешены: через них root-процесс
//! мог бы отправить содержимое чужого файла на сервер атакующего. Сертификаты и
//! ключи принимаются только во встроенных блоках `<ca>…</ca>`.

pub struct Filtered {
    pub text: String,
    pub dropped: Vec<String>,
}

/// Служебные директивы, которые helper всегда добавляет сам (и которые из
/// пользовательского файла отбрасываются): интерфейс, метка пакетов, MTU и
/// запрет скриптов.
pub const FIXED_SUFFIX: &str = "pull-filter ignore \"redirect-gateway\"\n\
pull-filter ignore \"dhcp-option DNS\"\n\
pull-filter ignore \"tun-mtu\"\n\
tun-mtu 1360\n\
mssfix 1320\n\
dev tun-ovpn\n\
mark 255\n\
script-security 0\n";

/// (имя, мин. аргументов, макс. аргументов)
const DIRECTIVES: &[(&str, usize, usize)] = &[
    // без аргументов
    ("client", 0, 0),
    ("tls-client", 0, 0),
    ("nobind", 0, 0),
    ("persist-key", 0, 0),
    ("persist-tun", 0, 0),
    ("float", 0, 0),
    ("auth-nocache", 0, 0),
    ("remote-random", 0, 0),
    ("pull", 0, 0),
    ("push-peer-info", 0, 0),
    ("mute-replay-warnings", 0, 0),
    ("route-nopull", 0, 0),
    // `auth-user-pass` только в форме без файла (учётные данные — во встроенном блоке)
    ("auth-user-pass", 0, 0),
    // подключение
    ("remote", 1, 3),
    ("proto", 1, 1),
    ("port", 1, 1),
    ("rport", 1, 1),
    ("lport", 1, 1),
    ("resolv-retry", 1, 1),
    ("connect-retry", 1, 2),
    ("connect-retry-max", 1, 1),
    ("connect-timeout", 1, 1),
    ("server-poll-timeout", 1, 1),
    ("socks-proxy", 1, 2),
    ("http-proxy", 1, 2),
    // TLS / шифры
    ("remote-cert-tls", 1, 1),
    ("ns-cert-type", 1, 1),
    ("peer-fingerprint", 1, 1),
    ("verify-hash", 1, 2),
    ("cipher", 1, 1),
    ("data-ciphers", 1, 1),
    ("data-ciphers-fallback", 1, 1),
    ("ncp-ciphers", 1, 1),
    ("auth", 1, 1),
    ("tls-cipher", 1, 1),
    ("tls-ciphersuites", 1, 1),
    ("tls-version-min", 1, 2),
    ("tls-version-max", 1, 1),
    ("key-direction", 1, 1),
    ("reneg-sec", 1, 2),
    ("reneg-bytes", 1, 1),
    ("reneg-pkts", 1, 1),
    ("tls-timeout", 1, 1),
    ("hand-window", 1, 1),
    ("tran-window", 1, 1),
    ("replay-window", 1, 2),
    // сжатие и буферы
    ("compress", 0, 1),
    ("comp-lzo", 0, 1),
    ("allow-compression", 1, 1),
    ("fragment", 1, 1),
    ("sndbuf", 1, 1),
    ("rcvbuf", 1, 1),
    // keepalive и логирование
    ("keepalive", 2, 2),
    ("ping", 1, 1),
    ("ping-restart", 1, 1),
    ("ping-exit", 1, 1),
    ("explicit-exit-notify", 0, 1),
    ("auth-retry", 1, 1),
    ("verb", 1, 1),
    ("mute", 1, 1),
    // маршруты (без исполнения команд)
    ("route", 1, 4),
    ("route-ipv6", 1, 3),
    ("route-delay", 0, 2),
    ("route-metric", 1, 1),
];

const BLOCK_TAGS: &[&str] = &[
    "ca",
    "cert",
    "key",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "dh",
    "extra-certs",
    "pkcs12",
    "secret",
    "crl-verify",
    "auth-user-pass",
];

const MAX_BLOCK_BYTES: usize = 64 * 1024;

fn arg_ok(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= 256
        && a
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b',' | b'+' | b'=' | b'/' | b'@' | b'-'))
}

pub fn filter(raw: &str) -> Result<Filtered, String> {
    if raw.contains('\0') {
        return Err("Конфигурация OpenVPN содержит нулевой байт".into());
    }
    let mut out = String::new();
    let mut dropped: Vec<String> = Vec::new();
    let note_drop = |name: &str, dropped: &mut Vec<String>| {
        let n: String = name.chars().take(40).collect();
        if !dropped.contains(&n) {
            dropped.push(n);
        }
    };

    let mut lines = raw.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        // Встроенный блок: строго `<tag>` на отдельной строке.
        if trimmed.starts_with('<') {
            let tag = trimmed.strip_prefix('<').and_then(|t| t.strip_suffix('>'));
            match tag {
                Some(t) if BLOCK_TAGS.contains(&t) => {
                    let close = format!("</{}>", t);
                    let mut body: Vec<String> = Vec::new();
                    let mut size = 0usize;
                    let mut closed = false;
                    for bl in lines.by_ref() {
                        let b = bl.trim_end_matches('\r').trim_end();
                        if b.trim() == close {
                            closed = true;
                            break;
                        }
                        if b.bytes().any(|c| !(c == b'\t' || (0x20..0x7f).contains(&c)) || c == b'<' || c == b'>') {
                            return Err(format!("Недопустимое содержимое во встроенном блоке <{}>", t));
                        }
                        size += b.len() + 1;
                        if size > MAX_BLOCK_BYTES {
                            return Err(format!("Блок <{}> слишком большой", t));
                        }
                        body.push(b.trim_start().to_string());
                    }
                    if !closed {
                        return Err(format!("Не закрыт блок <{}>", t));
                    }
                    out.push_str(&format!("<{}>\n", t));
                    for b in body {
                        if !b.is_empty() {
                            out.push_str(&b);
                            out.push('\n');
                        }
                    }
                    out.push_str(&close);
                    out.push('\n');
                }
                _ => note_drop(trimmed, &mut dropped),
            }
            continue;
        }

        // Обычная директива: токены до начала комментария.
        let mut tokens: Vec<&str> = Vec::new();
        for tok in trimmed.split_whitespace() {
            if tok.starts_with('#') || tok.starts_with(';') {
                break;
            }
            tokens.push(tok);
        }
        let name = match tokens.first() {
            Some(n) => *n,
            None => continue,
        };
        let args = &tokens[1..];

        let spec = DIRECTIVES.iter().find(|(n, _, _)| *n == name);
        match spec {
            Some((_, min, max)) if args.len() >= *min && args.len() <= *max && args.iter().all(|a| arg_ok(a)) => {
                out.push_str(name);
                for a in args {
                    out.push(' ');
                    out.push_str(a);
                }
                out.push('\n');
            }
            _ => note_drop(name, &mut dropped),
        }
    }

    Ok(Filtered { text: out, dropped })
}

/// Полный текст файла: отфильтрованный пользовательский конфиг + служебный хвост.
pub fn build(raw: &str) -> Result<Filtered, String> {
    let mut f = filter(raw)?;
    if !f.text.lines().any(|l| l.starts_with("remote ")) {
        return Err("В конфигурации OpenVPN нет ни одной директивы remote".into());
    }
    f.text.push_str(FIXED_SUFFIX);
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "client\ndev tun\nproto udp\nremote 203.0.113.9 1194\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\nverb 3\nkey-direction 1\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\nabcd\n-----END OpenVPN Static key V1-----\n</tls-auth>\n";

    #[test]
    fn typical_config_is_preserved() {
        let f = build(SAMPLE).unwrap();
        for must in ["client", "proto udp", "remote 203.0.113.9 1194", "cipher AES-256-GCM", "<ca>", "</ca>", "<tls-auth>", "key-direction 1", "MIIB"] {
            assert!(f.text.contains(must), "нет: {}", must);
        }
        // пользовательский dev заменён нашим
        assert_eq!(f.text.lines().filter(|l| *l == "dev tun").count(), 0);
        assert!(f.text.contains("dev tun-ovpn\n"));
        assert!(f.text.ends_with("script-security 0\n"));
        assert!(f.dropped.contains(&"dev".to_string()));
    }

    #[test]
    fn exec_directives_are_dropped() {
        let cfg = "client\nremote 1.2.3.4 1194\nup /tmp/x.sh\ndown /tmp/x.sh\nplugin /tmp/p.so\nscript-security 2\nroute-up /tmp/x\ntls-verify /tmp/x\nauth-user-pass-verify /tmp/x via-env\nsetenv FOO bar\nlearn-address /tmp/x\nipchange /tmp/x\nclient-connect /tmp/x\n";
        let f = build(cfg).unwrap();
        for bad in ["up ", "down ", "plugin", "route-up", "tls-verify", "auth-user-pass-verify", "setenv", "learn-address", "ipchange", "client-connect", "/tmp/"] {
            assert!(!f.text.contains(bad), "просочилось: {}", bad);
        }
        assert!(f.text.contains("script-security 0"));
        assert!(!f.text.contains("script-security 2"));
    }

    #[test]
    fn double_dash_and_case_tricks_do_not_bypass() {
        let cfg = "remote 1.2.3.4 1194\n--up /tmp/x.sh\nUP /tmp/x.sh\n--script-security 2\nPlugin /tmp/p.so\n";
        let f = build(cfg).unwrap();
        assert!(!f.text.contains("/tmp/"));
        assert!(!f.text.contains("script-security 2"));
    }

    #[test]
    fn file_reading_directives_are_dropped() {
        let cfg = "remote 1.2.3.4 1194\nca /etc/shadow\ncert /etc/shadow\nkey /root/.ssh/id_rsa\ntls-auth /etc/shadow 1\nauth-user-pass /etc/shadow\ncrl-verify /etc/shadow\nsecret /etc/shadow\nconfig /etc/other.conf\nlog /etc/sudoers.d/x\nstatus /etc/x\nwritepid /etc/x\nmanagement 127.0.0.1 7505\ndaemon\ncd /\nchroot /\nuser root\n";
        let f = build(cfg).unwrap();
        assert!(!f.text.contains("/etc/"));
        assert!(!f.text.contains("/root"));
        assert!(!f.text.contains("management"));
        assert!(!f.text.contains("daemon"));
    }

    #[test]
    fn bare_auth_user_pass_is_kept_but_with_file_is_not() {
        let f = build("remote 1.2.3.4 1194\nauth-user-pass\n").unwrap();
        assert!(f.text.contains("auth-user-pass\n"));
        let g = build("remote 1.2.3.4 1194\nauth-user-pass /tmp/creds\n").unwrap();
        assert!(!g.text.contains("/tmp/creds"));
    }

    #[test]
    fn quotes_backslashes_and_shell_chars_drop_directive() {
        let cfg = "remote 1.2.3.4 1194\ncipher \"AES-256-GCM\"\nauth SHA256;rm\nverb 3 $(id)\nproto udp`id`\nmute 5\\n\n";
        let f = build(cfg).unwrap();
        assert!(!f.text.contains("AES-256"));
        assert!(!f.text.contains("rm"));
        assert!(!f.text.contains("$("));
        assert!(!f.text.contains('`'));
        assert!(!f.text.contains("mute"));
    }

    #[test]
    fn inline_comment_is_cut() {
        let f = build("remote 1.2.3.4 1194 # comment up /x\nverb 3 ; trailing\n").unwrap();
        assert!(f.text.contains("remote 1.2.3.4 1194\n"));
        assert!(f.text.contains("verb 3\n"));
        assert!(!f.text.contains("comment"));
    }

    #[test]
    fn block_content_is_validated() {
        // '<' внутри блока — попытка прятать структуру
        let cfg = "remote 1.2.3.4 1194\n<ca>\nabc\n <up>\n</ca>\n";
        assert!(build(cfg).is_err());
        // незакрытый блок
        assert!(build("remote 1.2.3.4 1194\n<ca>\nabc\n").is_err());
        // непечатный символ
        assert!(build("remote 1.2.3.4 1194\n<ca>\nab\u{1}c\n</ca>\n").is_err());
    }

    #[test]
    fn directives_inside_block_are_data_not_emitted_as_directives() {
        let cfg = "remote 1.2.3.4 1194\n<ca>\nup /tmp/x.sh\n</ca>\n";
        let f = build(cfg).unwrap();
        // текст остаётся ВНУТРИ блока, а не как отдельная директива
        let before_close = f.text.split("</ca>").next().unwrap();
        assert!(before_close.contains("<ca>\nup /tmp/x.sh\n"));
        assert_eq!(f.text.lines().filter(|l| l.starts_with("up ")).count(), 1);
    }

    #[test]
    fn unknown_block_tags_dropped_but_not_parsed() {
        let cfg = "remote 1.2.3.4 1194\n<connection>\nremote 5.6.7.8\nup /x\n</connection>\n";
        let f = build(cfg).unwrap();
        assert!(!f.text.contains("connection"));
        assert!(!f.text.contains("up /x"));
    }

    #[test]
    fn arg_count_limits() {
        let cfg = "remote a b c d\nkeepalive 10\nverb 1 2\n";
        assert!(build(cfg).is_err()); // remote не прошёл — нет ни одного валидного remote
        let f = build("remote 1.2.3.4 1194\nkeepalive 10\nkeepalive 10 60\n").unwrap();
        assert!(f.text.contains("keepalive 10 60"));
        assert!(!f.text.contains("keepalive 10\n"));
    }

    #[test]
    fn requires_remote() {
        assert!(build("client\nnobind\n").is_err());
    }

    #[test]
    fn user_network_overrides_are_replaced_by_ours() {
        let cfg = "remote 1.2.3.4 1194\nmark 1\ntun-mtu 9000\nmssfix 100\nredirect-gateway def1\ndev tun0\ndev-type tun\npull-filter accept \"x\"\n";
        let f = build(cfg).unwrap();
        assert_eq!(f.text.matches("mark ").count(), 1);
        assert!(f.text.contains("mark 255"));
        assert!(!f.text.contains("9000"));
        assert!(!f.text.contains("redirect-gateway def1"));
        assert!(!f.text.contains("dev tun0"));
        assert!(!f.text.contains("accept"));
    }

    #[test]
    fn nul_byte_rejected() {
        assert!(build("remote 1.2.3.4 1194\0\n").is_err());
    }
}
