//! Серверный конец named pipe службы. Один экземпляр канала на всё время работы:
//! после каждого клиента он отключается и снова ждёт, а не закрывается. Так имя канала
//! ни на миг не освобождается и его не может занять чужой процесс.

use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_MORE_DATA, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_NONE, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

use super::sec::{last_error, wide, Sd};
use crate::winops::PIPE_NAME;

/// Права на канал: SYSTEM и администраторы — всё; вошедшие в систему пользователи (IU) —
/// только чтение и запись данных (0x12018b = FILE_GENERIC_READ | FILE_WRITE_DATA |
/// FILE_WRITE_ATTRIBUTES), без права создавать свои экземпляры канала; сетевым входам — запрет.
pub const PIPE_SDDL: &str = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12018b;;;IU)";

pub struct Server {
    h: HANDLE,
}

impl Server {
    pub fn create() -> Result<Server, String> {
        let sd = Sd::from_sddl(PIPE_SDDL)?;
        let sa = sd.attributes();
        let name = wide(PIPE_NAME);
        // SAFETY: имя с нулём на конце, sa и sd живы во время вызова.
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                &sa,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(format!("не удалось создать канал {} (уже занят?): {}", PIPE_NAME, last_error()));
        }
        Ok(Server { h })
    }

    pub fn handle(&self) -> HANDLE {
        self.h
    }

    /// Ждёт следующего клиента.
    pub fn accept(&self) -> Result<(), String> {
        // SAFETY: собственный дескриптор канала, синхронный режим.
        if unsafe { ConnectNamedPipe(self.h, null_mut()) } == 0 {
            // SAFETY: без аргументов.
            if unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
                return Err(format!("ConnectNamedPipe: {}", last_error()));
            }
        }
        Ok(())
    }

    /// Читает одно сообщение целиком, не больше `max` байт.
    pub fn read_message(&self, max: usize) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let mut n = 0u32;
            // SAFETY: буфер chunk длиной chunk.len(), синхронное чтение.
            let ok = unsafe { ReadFile(self.h, chunk.as_mut_ptr(), chunk.len() as u32, &mut n, null_mut()) };
            out.extend_from_slice(&chunk[..n as usize]);
            if out.len() > max {
                return Err("запрос слишком большой".into());
            }
            if ok != 0 {
                return Ok(out);
            }
            // SAFETY: без аргументов.
            if unsafe { GetLastError() } != ERROR_MORE_DATA {
                return Err(format!("ReadFile: {}", last_error()));
            }
        }
    }

    pub fn write_all(&self, data: &[u8]) -> Result<(), String> {
        let mut done = 0usize;
        while done < data.len() {
            let mut n = 0u32;
            let part = &data[done..];
            // SAFETY: part — живой срез, синхронная запись.
            let ok = unsafe { WriteFile(self.h, part.as_ptr(), part.len().min(u32::MAX as usize) as u32, &mut n, null_mut()) };
            if ok == 0 || n == 0 {
                return Err(format!("WriteFile: {}", last_error()));
            }
            done += n as usize;
        }
        Ok(())
    }

    /// Дожидается, пока клиент прочитает ответ, и отключает его.
    pub fn finish(&self) {
        // SAFETY: собственный дескриптор канала.
        unsafe {
            FlushFileBuffers(self.h);
            DisconnectNamedPipe(self.h);
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // SAFETY: дескриптор создан CreateNamedPipeW.
        unsafe { CloseHandle(self.h) };
    }
}

/// Будит службу, ждущую клиента в `accept`: подключается к каналу и сразу закрывает его.
pub fn wake() {
    let name = wide(PIPE_NAME);
    // SAFETY: имя с нулём на конце; дескриптор сразу закрывается.
    unsafe {
        let h = CreateFileW(name.as_ptr(), 0x8000_0000 /* GENERIC_READ */, FILE_SHARE_NONE, null_mut(), OPEN_EXISTING, 0, null_mut());
        if h != INVALID_HANDLE_VALUE {
            CloseHandle(h);
        }
    }
}
