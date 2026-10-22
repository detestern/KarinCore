//! Клиент службы KarinCore на Windows (аналог `sudo -n karincore-helper` на Linux).
//!
//! Запрос и ответ — тот же протокол `KARIN-HELPER/1`, только через named pipe.
//! Перед отправкой проверяем, что на другом конце канала именно служба KarinCore:
//! PID сервера канала должен совпасть с PID службы, который сообщает диспетчер служб.
//! Иначе чужая программа могла бы занять имя канала и получить конфигурацию с ключами.

use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
    ERROR_PIPE_NOT_CONNECTED, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DISABLED, ERROR_SERVICE_DOES_NOT_EXIST,
    GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_SHARE_NONE, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS_PROCESS,
};

const PIPE_NAME: &str = r"\\.\pipe\karincore-helper";
const SERVICE_NAME: &str = "KarinCore";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error_code() -> u32 {
    // SAFETY: без аргументов.
    unsafe { GetLastError() }
}

fn describe(code: u32) -> String {
    format!("{} (код {})", std::io::Error::from_raw_os_error(code as i32), code)
}

struct Scm(SC_HANDLE);

impl Drop for Scm {
    fn drop(&mut self) {
        // SAFETY: дескриптор открыт OpenSCManagerW/OpenServiceW.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn open_service(access: u32) -> Result<(Scm, Scm), String> {
    // SAFETY: локальный компьютер, база по умолчанию.
    let scm = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return Err(format!("Не удалось связаться с диспетчером служб Windows: {}", describe(last_error_code())));
    }
    let scm = Scm(scm);
    let name = wide(SERVICE_NAME);
    // SAFETY: имя с нулём на конце.
    let svc = unsafe { OpenServiceW(scm.0, name.as_ptr(), access) };
    if svc.is_null() {
        return Err(match last_error_code() {
            ERROR_SERVICE_DOES_NOT_EXIST => "Служба KarinCore не установлена. Переустановите KarinCore.".to_string(),
            ERROR_ACCESS_DENIED => "Нет доступа к службе KarinCore. Переустановите KarinCore.".to_string(),
            code => format!("Не удалось открыть службу KarinCore: {}", describe(code)),
        });
    }
    Ok((scm, Scm(svc)))
}

fn start_service() -> Result<(), String> {
    let (_scm, svc) = open_service(SERVICE_START | SERVICE_QUERY_STATUS)?;
    // SAFETY: без аргументов службы.
    if unsafe { StartServiceW(svc.0, 0, null()) } == 0 {
        return match last_error_code() {
            ERROR_SERVICE_ALREADY_RUNNING => Ok(()),
            ERROR_SERVICE_DISABLED => Err("Служба KarinCore отключена в «Службах» Windows. Включите её (тип запуска «Вручную»).".into()),
            code => Err(format!("Не удалось запустить службу KarinCore: {}", describe(code))),
        };
    }
    Ok(())
}

/// PID работающей службы по данным диспетчера служб (0 — служба не запущена).
fn service_pid() -> Result<u32, String> {
    let (_scm, svc) = open_service(SERVICE_QUERY_STATUS)?;
    // SAFETY: обнулённая структура из одних чисел.
    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut needed = 0u32;
    // SAFETY: буфер — status нужного размера.
    let ok = unsafe {
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(format!("Не удалось узнать состояние службы KarinCore: {}", describe(last_error_code())));
    }
    Ok(status.dwProcessId)
}

struct Pipe(HANDLE);

impl Drop for Pipe {
    fn drop(&mut self) {
        // SAFETY: дескриптор открыт CreateFileW.
        unsafe { CloseHandle(self.0) };
    }
}

/// `None` — служба не запущена, а запускать её ради этого запроса не нужно.
fn connect(start_if_needed: bool) -> Result<Option<Pipe>, String> {
    let name = wide(PIPE_NAME);
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut started = false;
    loop {
        // SECURITY_IDENTIFICATION: служба узнаёт, кто мы, но не может действовать от нашего имени.
        // SAFETY: имя с нулём на конце, остальное — константы.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | FILE_WRITE_DATA,
                FILE_SHARE_NONE,
                null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            return Ok(Some(Pipe(h)));
        }
        let code = last_error_code();
        if Instant::now() > deadline {
            return Err("Служба KarinCore не отвечает. Перезапустите компьютер или переустановите KarinCore.".into());
        }
        match code {
            ERROR_FILE_NOT_FOUND => {
                if !start_if_needed && !started {
                    return Ok(None);
                }
                // Служба запускается по требованию: при первом обращении поднимаем её сами.
                if !started {
                    start_service()?;
                    started = true;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            ERROR_PIPE_BUSY => {
                // SAFETY: имя с нулём на конце.
                unsafe { WaitNamedPipeW(name.as_ptr(), 2000) };
            }
            ERROR_ACCESS_DENIED => return Err("Нет доступа к службе KarinCore.".into()),
            code => return Err(format!("Не удалось подключиться к службе KarinCore: {}", describe(code))),
        }
    }
}

fn verify_server(pipe: &Pipe) -> Result<(), String> {
    let mut pid = 0u32;
    // SAFETY: открытый клиентский конец канала.
    if unsafe { GetNamedPipeServerProcessId(pipe.0, &mut pid) } == 0 {
        return Err(format!("Не удалось проверить службу KarinCore: {}", describe(last_error_code())));
    }
    let expected = service_pid()?;
    if pid == 0 || pid != expected {
        return Err("Канал службы KarinCore открыт другой программой. Подключение отменено ради безопасности.".into());
    }
    Ok(())
}

fn write_all(pipe: &Pipe, data: &[u8]) -> Result<(), String> {
    let mut done = 0usize;
    while done < data.len() {
        let part = &data[done..];
        let mut n = 0u32;
        // SAFETY: part — живой срез, синхронная запись.
        let ok = unsafe { WriteFile(pipe.0, part.as_ptr(), part.len().min(u32::MAX as usize) as u32, &mut n, null_mut()) };
        if ok == 0 || n == 0 {
            return Err(format!("Ошибка отправки запроса службе KarinCore: {}", describe(last_error_code())));
        }
        done += n as usize;
    }
    Ok(())
}

fn read_to_end(pipe: &Pipe) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        let mut n = 0u32;
        // SAFETY: буфер chunk длиной chunk.len(), синхронное чтение.
        let ok = unsafe { ReadFile(pipe.0, chunk.as_mut_ptr(), chunk.len() as u32, &mut n, null_mut()) };
        out.extend_from_slice(&chunk[..n as usize]);
        if ok != 0 {
            if n == 0 {
                return Ok(out);
            }
            continue;
        }
        return match last_error_code() {
            // служба ответила и отключилась — это конец ответа
            ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED => Ok(out),
            code => Err(format!("Ошибка чтения ответа службы KarinCore: {}", describe(code))),
        };
    }
}

/// Отправляет один запрос и возвращает сырой ответ службы.
/// `None` — служба не запущена и `start_if_needed` не задан: запрос не отправлялся.
pub fn transact(message: &[u8], start_if_needed: bool) -> Result<Option<Vec<u8>>, String> {
    let Some(pipe) = connect(start_if_needed)? else { return Ok(None) };
    verify_server(&pipe)?;
    write_all(&pipe, message)?;
    read_to_end(&pipe).map(Some)
}
