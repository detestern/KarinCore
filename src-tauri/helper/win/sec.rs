//! Права доступа Windows: дескрипторы безопасности из SDDL, DACL на файлы и каталоги,
//! владелец каталога и SID пользователя на другом конце named pipe.

use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetTokenInformation, IsWellKnownSid, RevertToSelf, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

/// Строка с завершающим нулём в UTF-16.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn wide_path(p: &Path) -> Result<Vec<u16>, String> {
    p.to_str().map(wide).ok_or_else(|| format!("путь не в UTF-8: {}", p.display()))
}

pub fn last_error() -> String {
    // SAFETY: без аргументов, только читает код ошибки потока.
    let code = unsafe { GetLastError() };
    format!("{} (код {})", std::io::Error::from_raw_os_error(code as i32), code)
}

/// Дескриптор безопасности, созданный из SDDL; освобождается в Drop.
pub struct Sd(PSECURITY_DESCRIPTOR);

impl Sd {
    pub fn from_sddl(sddl: &str) -> Result<Sd, String> {
        let w = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: строка с нулём на конце; sd получает память LocalAlloc, её освобождает Drop.
        let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) };
        if ok == 0 || sd.is_null() {
            return Err(format!("некорректный SDDL: {}", last_error()));
        }
        Ok(Sd(sd))
    }

    /// SECURITY_ATTRIBUTES, ссылающиеся на этот дескриптор (живут не дольше `self`).
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    fn dacl(&self) -> Result<*mut ACL, String> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: self.0 — действительный дескриптор, выходные указатели на локальные переменные.
        let ok = unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) };
        if ok == 0 || present == 0 || dacl.is_null() {
            return Err("в SDDL нет DACL".into());
        }
        Ok(dacl)
    }
}

impl Drop for Sd {
    fn drop(&mut self) {
        // SAFETY: память выделена ConvertStringSecurityDescriptorToSecurityDescriptorW (LocalAlloc).
        unsafe { LocalFree(self.0) };
    }
}

/// Ставит защищённый DACL (наследование от родителя отключается).
pub fn set_dacl(path: &Path, sddl: &str) -> Result<(), String> {
    let sd = Sd::from_sddl(sddl)?;
    let dacl = sd.dacl()?;
    let w = wide_path(path)?;
    // SAFETY: путь с нулём на конце, DACL живёт, пока жив sd.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!(
            "не удалось выставить права на {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(rc as i32)
        ));
    }
    Ok(())
}

/// Владелец — SYSTEM или группа администраторов. Каталог, созданный обычным пользователем
/// заранее (в ProgramData это разрешено), служба использовать не будет.
pub fn owned_by_system_or_admins(path: &Path) -> Result<bool, String> {
    let w = wide_path(path)?;
    let mut owner: PSID = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: выходные указатели на локальные переменные; sd освобождаем LocalFree.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!(
            "не удалось прочитать владельца {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(rc as i32)
        ));
    }
    // SAFETY: owner указывает внутрь sd, который ещё не освобождён.
    let ok = unsafe { IsWellKnownSid(owner, WinLocalSystemSid) != 0 || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0 };
    // SAFETY: sd выделен GetNamedSecurityInfoW.
    unsafe { LocalFree(sd) };
    Ok(ok)
}

/// SID пользователя из токена в виде строки `S-1-…`.
fn token_user_sid(token: HANDLE) -> Result<String, String> {
    let mut len = 0u32;
    // SAFETY: первый вызов только узнаёт нужный размер.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
    if len == 0 || len > 4096 {
        return Err(format!("GetTokenInformation: {}", last_error()));
    }
    // u64 — чтобы буфер был выровнен под TOKEN_USER.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: буфер не меньше len байт.
    let ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) };
    if ok == 0 {
        return Err(format!("GetTokenInformation: {}", last_error()));
    }
    // SAFETY: Windows записала в буфер структуру TOKEN_USER.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    let mut s: windows_sys::core::PWSTR = null_mut();
    // SAFETY: sid указывает внутрь buf; строку освобождаем LocalFree.
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 || s.is_null() {
        return Err(format!("ConvertSidToStringSidW: {}", last_error()));
    }
    let mut n = 0;
    // SAFETY: строка с нулём на конце, выделена Windows.
    let text = unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(s, n))
    };
    // SAFETY: память выделена ConvertSidToStringSidW (LocalAlloc).
    unsafe { LocalFree(s.cast()) };
    Ok(text)
}

/// SID пользователя, подключившегося к каналу. Клиент открывает канал с уровнем
/// SECURITY_IDENTIFICATION: служба может узнать, кто это, но не действовать от его имени.
pub fn pipe_client_sid(pipe: HANDLE) -> Result<String, String> {
    // SAFETY: pipe — открытый серверный конец канала с подключённым клиентом.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(format!("ImpersonateNamedPipeClient: {}", last_error()));
    }
    let res = (|| {
        let mut token: HANDLE = null_mut();
        // SAFETY: токен текущего потока (сейчас — клиента); проверка доступа от имени службы.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            return Err(format!("OpenThreadToken: {}", last_error()));
        }
        let sid = token_user_sid(token);
        // SAFETY: токен открыт выше.
        unsafe { CloseHandle(token) };
        sid
    })();
    // SAFETY: без аргументов. Если поток не вернулся к правам службы, продолжать нельзя.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
    res
}
