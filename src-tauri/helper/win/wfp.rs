//! Kill Switch на Windows Filtering Platform.
//!
//! Фильтры живут в собственном подслое KarinCore с максимальным весом. В Windows решение
//! принимает каждый подслой отдельно, и блокировка в любом из них сильнее разрешения в другом,
//! поэтому разрешающие правила других программ (в том числе брандмауэра Windows) наш блок
//! не обходят.
//!
//! Сессия обычная, не динамическая, а фильтры без флага PERSISTENT: они переживают падение
//! службы, приложения и xray.exe (защита остаётся), но не перезагрузку — после неё сеть
//! гарантированно возвращается. Всё ставится и снимается одной транзакцией: либо все
//! фильтры на месте, либо ни одного.

use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_NONE,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_SESSION0, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_MATCH_EQUAL,
    FWP_MATCH_FLAGS_ALL_SET, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::sec::wide;
use crate::winops::{kill_switch_plan, KsCond, KsLayer, KS_MAX_FILTERS, TUN_IFACE};

/// Подслой KarinCore (постоянный ключ: по нему фильтры находятся и после перезапуска службы).
const SUBLAYER_KEY: GUID = GUID::from_u128(0x422b50b1_b268_4523_bd13_cf48929a8e39);
/// Ключ фильтра номер i — `FILTER_KEY_BASE + i`. Снимаются все KS_MAX_FILTERS ключей.
const FILTER_KEY_BASE: u128 = 0x2c34eadf_f416_46a9_910d_aacad8db0000;

fn filter_key(i: usize) -> GUID {
    GUID::from_u128(FILTER_KEY_BASE + i as u128)
}

fn layer_key(l: KsLayer) -> GUID {
    match l {
        KsLayer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        KsLayer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        KsLayer::AcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        KsLayer::AcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

fn check(what: &str, rc: u32) -> Result<(), String> {
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("{}: ошибка WFP 0x{:08X}", what, rc))
    }
}

/// Открытый движок WFP; закрывается в Drop. Если транзакция не зафиксирована, она откатывается.
struct Engine {
    h: HANDLE,
    in_txn: bool,
}

impl Engine {
    fn open() -> Result<Engine, String> {
        let name = wide("KarinCore Kill Switch");
        // SAFETY: обнулённая структура из чисел и указателей; затем заполняем нужные поля.
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.displayData.name = name.as_ptr() as *mut u16;
        // flags = 0: не динамическая сессия, фильтры переживают закрытие движка и смерть процесса.
        let mut h: HANDLE = null_mut();
        // SAFETY: локальный движок, структуры живут во время вызова.
        let rc = unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut h) };
        check("FwpmEngineOpen0", rc)?;
        Ok(Engine { h, in_txn: false })
    }

    fn begin(&mut self) -> Result<(), String> {
        // SAFETY: открытый движок.
        check("FwpmTransactionBegin0", unsafe { FwpmTransactionBegin0(self.h, 0) })?;
        self.in_txn = true;
        Ok(())
    }

    fn commit(&mut self) -> Result<(), String> {
        self.in_txn = false;
        // SAFETY: открытый движок с начатой транзакцией.
        check("FwpmTransactionCommit0", unsafe { FwpmTransactionCommit0(self.h) })
    }

    /// Удаляет все наши фильтры и подслой; «уже нет» ошибкой не считается.
    fn remove_all(&self) -> Result<(), String> {
        for i in 0..KS_MAX_FILTERS {
            let key = filter_key(i);
            // SAFETY: открытый движок, ключ живёт во время вызова.
            let rc = unsafe { FwpmFilterDeleteByKey0(self.h, &key) };
            if rc != 0 && rc != FWP_E_FILTER_NOT_FOUND as u32 {
                return check("FwpmFilterDeleteByKey0", rc);
            }
        }
        // SAFETY: то же.
        let rc = unsafe { FwpmSubLayerDeleteByKey0(self.h, &SUBLAYER_KEY) };
        if rc != 0 && rc != FWP_E_SUBLAYER_NOT_FOUND as u32 {
            return check("FwpmSubLayerDeleteByKey0", rc);
        }
        Ok(())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: открытый движок; незафиксированная транзакция откатывается целиком.
        unsafe {
            if self.in_txn {
                FwpmTransactionAbort0(self.h);
            }
            FwpmEngineClose0(self.h);
        }
    }
}

/// App ID для условия ALE_APP_ID; память освобождается в Drop.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn of(path: &Path) -> Result<AppId, String> {
        let w = super::sec::wide_path(path)?;
        let mut blob: *mut FWP_BYTE_BLOB = null_mut();
        // SAFETY: путь с нулём на конце; blob выделяет WFP, освобождаем FwpmFreeMemory0.
        let rc = unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut blob) };
        check(&format!("FwpmGetAppIdFromFileName0({})", path.display()), rc)?;
        Ok(AppId(blob))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        let mut p = self.0.cast::<std::ffi::c_void>();
        // SAFETY: память выделена FwpmGetAppIdFromFileName0.
        unsafe { FwpmFreeMemory0(&mut p) };
    }
}

fn tun_luid() -> Result<u64, String> {
    let alias = wide(TUN_IFACE);
    // Адаптер появляется через пару секунд после запуска Xray: даём ему время.
    for _ in 0..25 {
        // SAFETY: обнулённый union из чисел.
        let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
        // SAFETY: строка с нулём на конце, выходной параметр — локальная переменная.
        if unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } == 0 {
            // SAFETY: Value — представление всего union как u64.
            return Ok(unsafe { luid.Value });
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err(format!("не найден сетевой адаптер {}: туннель не поднялся", TUN_IFACE))
}

/// Ставит Kill Switch. Перед этим снимает прежний (в той же транзакции).
pub fn ks_on(xray_exe: &Path) -> Result<(), String> {
    let mut luid = tun_luid()?;
    let app = AppId::of(xray_exe)?;
    let mut e = Engine::open()?;
    e.begin()?;
    e.remove_all()?;

    let name = wide("KarinCore Kill Switch");
    // SAFETY: обнулённая структура; заполняем ключ, имя и вес.
    let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sub.subLayerKey = SUBLAYER_KEY;
    sub.displayData.name = name.as_ptr() as *mut u16;
    sub.weight = u16::MAX;
    // SAFETY: открытый движок с транзакцией, структура живёт во время вызова.
    check("FwpmSubLayerAdd0", unsafe { FwpmSubLayerAdd0(e.h, &sub, null_mut()) })?;

    for (i, f) in kill_switch_plan().iter().enumerate() {
        let mut conds: Vec<FWPM_FILTER_CONDITION0> = f
            .conds
            .iter()
            .map(|c| {
                // SAFETY: обнулённое значение условия; ниже заполняем тип и данные.
                let mut v: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
                let (field, mt) = match *c {
                    KsCond::Loopback => {
                        v.r#type = FWP_UINT32;
                        v.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                        (FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET)
                    }
                    KsCond::CoreApp => {
                        v.r#type = FWP_BYTE_BLOB_TYPE;
                        v.Anonymous.byteBlob = app.0;
                        (FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL)
                    }
                    KsCond::TunInterface => {
                        v.r#type = FWP_UINT64;
                        v.Anonymous.uint64 = &mut luid;
                        (FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_EQUAL)
                    }
                    KsCond::Protocol(p) => {
                        v.r#type = FWP_UINT8;
                        v.Anonymous.uint8 = p;
                        (FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL)
                    }
                    KsCond::LocalPort(p) => {
                        v.r#type = FWP_UINT16;
                        v.Anonymous.uint16 = p;
                        (FWPM_CONDITION_IP_LOCAL_PORT, FWP_MATCH_EQUAL)
                    }
                    KsCond::RemotePort(p) => {
                        v.r#type = FWP_UINT16;
                        v.Anonymous.uint16 = p;
                        (FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL)
                    }
                };
                FWPM_FILTER_CONDITION0 { fieldKey: field, matchType: mt, conditionValue: v }
            })
            .collect();

        // SAFETY: обнулённая структура фильтра; заполняем нужные поля.
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.filterKey = filter_key(i);
        filter.displayData.name = name.as_ptr() as *mut u16;
        filter.flags = FWPM_FILTER_FLAG_NONE;
        filter.layerKey = layer_key(f.layer);
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = f.weight;
        filter.numFilterConditions = conds.len() as u32;
        filter.filterCondition = if conds.is_empty() { null_mut() } else { conds.as_mut_ptr() };
        filter.action.r#type = if f.permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
        // SAFETY: движок с транзакцией; условия, app id и luid живы во время вызова.
        let rc = unsafe { FwpmFilterAdd0(e.h, &filter, null_mut(), null_mut()) };
        check(&format!("FwpmFilterAdd0 (фильтр {})", i), rc)?;
    }
    e.commit()
}

pub fn ks_off() -> Result<(), String> {
    let mut e = Engine::open()?;
    e.begin()?;
    e.remove_all()?;
    e.commit()
}
