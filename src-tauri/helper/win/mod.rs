//! Служба KarinCore для Windows. Работает от SYSTEM и принимает запросы GUI через
//! named pipe `\\.\pipe\karincore-helper`; что и как выполняется — в `winops.rs`.
//!
//! Запуск: `karincore-helper.exe --service` (так служба зарегистрирована установщиком).
//! Для отладки администратор может запустить `--console`: тот же цикл, но в окне консоли.

mod cmd;
mod os;
mod pipe;
mod sec;
mod service;
mod wfp;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::winops::{self, Ctx, Paths, State, MAX_MESSAGE};

fn paths() -> Result<Paths, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {}", e))?;
    let install = exe.parent().ok_or("нет каталога установки")?.to_path_buf();
    let program_data = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    Ok(Paths { data: program_data.join("KarinCore"), install })
}

/// Журнал самой службы: `%ProgramData%\KarinCore\service.log` (читают только SYSTEM и администраторы).
fn log(text: &str) {
    let Ok(p) = paths() else { return };
    if fs::create_dir_all(&p.data).is_err() {
        return;
    }
    let file = p.data.join("service.log");
    if fs::metadata(&file).map(|m| m.len() > 1024 * 1024).unwrap_or(false) {
        let _ = fs::write(&file, "");
    }
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&file) {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let _ = writeln!(f, "[{}] {}", secs, text);
    }
}

/// Проверяет каталог данных: если его заранее создал не администратор, служба им не пользуется.
fn check_data_dir(p: &Paths) -> Result<(), String> {
    if p.data.exists() && !sec::owned_by_system_or_admins(&p.data)? {
        return Err(format!(
            "Каталог {} создан не администратором. Удалите его и запустите KarinCore снова.",
            p.data.display()
        ));
    }
    Ok(())
}

/// Основной цикл: ждёт клиента, выполняет один запрос, отвечает, повторяет.
pub fn serve(stop: &AtomicBool) -> Result<(), String> {
    let p = paths()?;
    check_data_dir(&p)?;
    let os = os::WinOs::default();
    winops::Os::secure_dir(&os, &p.data, None)?;
    let server = pipe::Server::create()?;
    // Настройка TUN-адаптера занимает пару секунд: если она не удалась, Xray к этому времени уже завершится.
    let ctx = Ctx { paths: &p, os: &os, settle_ms: 2500 };
    let mut state = State::default();
    log("служба запущена");

    let mut failures = 0;
    while !stop.load(Ordering::SeqCst) && !state.stop_requested {
        if let Err(e) = server.accept() {
            log(&e);
            failures += 1;
            if failures > 20 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            continue;
        }
        failures = 0;
        if stop.load(Ordering::SeqCst) {
            server.finish();
            break;
        }
        let answer = match server.read_message(MAX_MESSAGE) {
            Ok(msg) => {
                let caller = sec::pipe_client_sid(server.handle()).unwrap_or_else(|e| {
                    log(&e);
                    String::new()
                });
                winops::handle_message(&ctx, &mut state, &msg, &caller)
            }
            Err(e) => winops::reply(&Err(e)),
        };
        let _ = server.write_all(&answer);
        server.finish();
    }

    winops::Os::core_stop(&os);
    log("служба остановлена");
    Ok(())
}

pub fn main() -> i32 {
    match std::env::args().nth(1).as_deref() {
        Some("--service") => service::run(),
        // Для деинсталлятора (он работает от администратора): снять Kill Switch, если он остался.
        Some("--ks-off") => match wfp::ks_off() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("karincore-helper: {}", e);
                1
            }
        },
        Some("--console") => {
            static CONSOLE_STOP: AtomicBool = AtomicBool::new(false);
            match serve(&CONSOLE_STOP) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("karincore-helper: {}", e);
                    1
                }
            }
        }
        _ => {
            eprintln!("karincore-helper: служба KarinCore. Её запускает Windows; для отладки: --console (от администратора).");
            2
        }
    }
}
