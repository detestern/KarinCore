//! Реализация [`Os`] для Windows: права на каталоги и файлы и процесс Xray.

use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use super::sec::set_dacl;
use crate::winops::{dacl_sddl, Os, Paths};

#[derive(Default)]
pub struct WinOs {
    child: RefCell<Option<Child>>,
}

impl Os for WinOs {
    fn secure_dir(&self, dir: &Path, reader: Option<&str>) -> Result<(), String> {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
        set_dacl(dir, &dacl_sddl(reader, true)?)
    }

    fn secure_file(&self, file: &Path, reader: Option<&str>) -> Result<(), String> {
        set_dacl(file, &dacl_sddl(reader, false)?)
    }

    fn core_start(&self, paths: &Paths) -> Result<(), String> {
        self.core_stop();
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(paths.console_log())
            .map_err(|e| format!("{}: {}", paths.console_log().display(), e))?;
        let log2 = log.try_clone().map_err(|e| e.to_string())?;
        let mut cmd = Command::new(paths.xray_exe());
        cmd.arg("run")
            .arg("-c")
            .arg(paths.config_file())
            .current_dir(paths.core_dir())
            // geoip.dat и geosite.dat лежат рядом с xray.exe
            .env("XRAY_LOCATION_ASSET", paths.core_dir())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2));
        super::cmd::no_window(&mut cmd);
        let child = cmd.spawn().map_err(|e| format!("Не удалось запустить {}: {}", paths.xray_exe().display(), e))?;
        *self.child.borrow_mut() = Some(child);
        Ok(())
    }

    fn core_stop(&self) {
        if let Some(mut c) = self.child.borrow_mut().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn core_running(&self) -> bool {
        let mut slot = self.child.borrow_mut();
        let alive = match slot.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        };
        if !alive {
            if let Some(mut c) = slot.take() {
                let _ = c.wait();
            }
        }
        alive
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}
