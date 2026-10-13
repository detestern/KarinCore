//! karincore-helper — привилегированная сторона KarinCore.
//!
//! GUI работает от обычного пользователя и больше не получает от sudoers набор
//! «голых» команд (`cp`, `openvpn`, `wg-quick`, `iptables -d *`, …). Вместо этого
//! sudoers разрешает запускать ровно этот бинарник без аргументов, а запрос
//! приходит через stdin (см. `proto.rs`). Helper сам проверяет параметры и
//! конфигурации и выполняет фиксированный набор действий.
//!
//! Зависимостей нет: бинарник работает от root, поэтому его поверхность
//! атаки должна быть минимальной.

mod json;
mod ops;
mod ovpn;
mod proto;
mod sys;
mod wg;
mod xray;

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

fn reply(ok: bool, msg: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", if ok { "OK" } else { "ERR" });
    if !msg.is_empty() {
        let _ = writeln!(out, "{}", msg);
    }
    let _ = out.flush();
}

fn running_as_root() -> bool {
    fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false)
}

fn run() -> i32 {
    let stdin = std::io::stdin();
    let req = match proto::read_request(&mut stdin.lock()) {
        Ok(r) => r,
        Err(e) => {
            reply(false, &e);
            return 2;
        }
    };

    // `version` не требует прав — им GUI проверяет, что helper установлен.
    if req.op != "version" && !running_as_root() {
        reply(false, "helper должен запускаться через sudo (от root)");
        return 3;
    }

    let ctx = ops::Ctx { paths: sys::Paths::system(), run: Box::new(sys::SysRunner), settle_ms: 100 };

    // Одновременные вызовы (например, подключение и закрытие окна) выполняем по очереди.
    let _lock = if req.op != "version" {
        match sys::ensure_dir(&ctx.paths.run_dir, 0o755, ctx.paths.owner_uid).and_then(|_| {
            fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(ctx.paths.lock_file())
                .map_err(|e| e.to_string())
        }) {
            Ok(f) => {
                let _ = f.lock();
                Some(f)
            }
            Err(e) => {
                reply(false, &format!("не удалось подготовить каталог состояния: {}", e));
                return 1;
            }
        }
    } else {
        None
    };

    match ops::dispatch(&ctx, &req) {
        Ok(msg) => {
            reply(true, &msg);
            0
        }
        Err(e) => {
            reply(false, &e);
            1
        }
    }
}

fn main() {
    std::process::exit(run());
}
