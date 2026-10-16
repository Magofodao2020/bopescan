// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Permanent WMI event subscriptions, read through WMI's documented query interface (B.O.P.E,
//! ADR 0127).
//!
//! `IWbemLocator::ConnectServer` to the namespace, then `IWbemServices::ExecQuery` with
//! `SELECT * FROM <class>` and `IWbemClassObject::Get` for each named property. Nothing else of
//! `IWbemServices` is called: no `PutInstance`, `DeleteInstance`, `ExecMethod` or event delivery, so
//! reading changes no subscription and starts no consumer. The work runs on its own thread, which
//! joins the multithreaded apartment and leaves it again, so the caller's COM state is untouched.
//! `CoInitializeSecurity` is not called: it is process-wide.

use bope_host::{SourceError, WmiObject, WmiSubscriptionClass};

/// `WBEM_E_INVALID_NAMESPACE`: the namespace does not exist.
pub const WBEM_E_INVALID_NAMESPACE: u32 = 0x8004_100E;
/// `WBEM_E_ACCESS_DENIED`.
pub const WBEM_E_ACCESS_DENIED: u32 = 0x8004_1003;
/// `E_ACCESSDENIED`.
pub const E_ACCESSDENIED: u32 = 0x8007_0005;
/// `WBEM_E_INVALID_CLASS`: the class is not defined in that namespace.
pub const WBEM_E_INVALID_CLASS: u32 = 0x8004_1010;
/// Most objects read from one query.
pub const MAX_OBJECTS: usize = 2_000;

/// What an `HRESULT` from WMI means to a caller: `None` for "nothing there".
pub fn classify(code: u32, context: &str) -> Option<SourceError> {
    match code {
        WBEM_E_INVALID_NAMESPACE | WBEM_E_INVALID_CLASS => None,
        WBEM_E_ACCESS_DENIED | E_ACCESSDENIED => Some(SourceError::AccessDenied),
        other => Some(SourceError::Failed(format!("{context}: 0x{other:08X}"))),
    }
}

#[cfg(windows)]
impl bope_host::WmiSubscriptionSource for crate::LiveHost {
    fn wmi_objects(
        &self,
        namespace: &str,
        class: WmiSubscriptionClass,
        properties: &[&str],
    ) -> Result<Option<Vec<WmiObject>>, SourceError> {
        let namespace = namespace.to_owned();
        let properties: Vec<String> = properties.iter().map(|p| (*p).to_owned()).collect();
        std::thread::spawn(move || query(&namespace, class, &properties))
            .join()
            .unwrap_or_else(|_| Err(SourceError::Failed("the WMI thread stopped".to_owned())))
    }
}

#[cfg(windows)]
#[allow(unsafe_code, clippy::too_many_lines)]
fn query(
    namespace: &str,
    class: WmiSubscriptionClass,
    properties: &[String],
) -> Result<Option<Vec<WmiObject>>, SourceError> {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
    use windows::Win32::System::Variant::{
        VARIANT, VT_BOOL, VT_BSTR, VT_I2, VT_I4, VT_UI1, VT_UI2, VT_UI4, VariantClear,
    };
    use windows::Win32::System::Wmi::{
        IWbemClassObject, IWbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
        WBEM_INFINITE, WbemLocator,
    };
    use windows::core::{BSTR, HSTRING, PCWSTR};

    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            // SAFETY: paired with the successful `CoInitializeEx` below, on this same thread.
            unsafe { CoUninitialize() };
        }
    }

    let code = |e: &windows::core::Error| e.code().0.cast_unsigned();
    // SAFETY: called once on a thread this function owns; no pointer is passed.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
        .ok()
        .map_err(|e| SourceError::Failed(format!("CoInitializeEx: 0x{:08X}", code(&e))))?;
    let _apartment = Apartment;
    // SAFETY: `WbemLocator` is the documented class id for `IWbemLocator`; no outer object.
    let locator: IWbemLocator =
        unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| SourceError::Failed(format!("CoCreateInstance: 0x{:08X}", code(&e))))?;
    // SAFETY: every argument is an owned `BSTR` that outlives the call; no context object.
    let services = match unsafe {
        locator.ConnectServer(
            &BSTR::from(namespace),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )
    } {
        Ok(s) => s,
        Err(e) => {
            return match classify(code(&e), "ConnectServer") {
                None => Ok(None),
                Some(err) => Err(err),
            };
        }
    };
    // SAFETY: `services` is a live proxy; the constants are the documented local-call values.
    unsafe {
        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    }
    .map_err(|e| SourceError::Failed(format!("CoSetProxyBlanket: 0x{:08X}", code(&e))))?;
    let text = format!("SELECT * FROM {}", class.wmi_class());
    // SAFETY: owned `BSTR`s; flags are the documented read-only enumeration flags.
    let rows = match unsafe {
        services.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(text.as_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
    } {
        Ok(r) => r,
        Err(e) => {
            return match classify(code(&e), "ExecQuery") {
                None => Ok(Some(Vec::new())),
                Some(err) => Err(err),
            };
        }
    };
    let read = |object: &IWbemClassObject, name: &str| -> Option<String> {
        let wide = HSTRING::from(name);
        let mut value = VARIANT::default();
        // SAFETY: `value` is a zeroed VARIANT this closure owns and clears below; `wide` lives
        // across the call.
        let got = unsafe { object.Get(PCWSTR(wide.as_ptr()), 0, &raw mut value, None, None) };
        if got.is_err() {
            return None;
        }
        // SAFETY: the union member read is the one `vt` names, per the VARIANT contract.
        let out = unsafe {
            let inner = &value.Anonymous.Anonymous;
            match inner.vt {
                VT_BSTR => Some(inner.Anonymous.bstrVal.to_string()),
                VT_I4 => Some(inner.Anonymous.lVal.to_string()),
                VT_UI4 => Some(inner.Anonymous.ulVal.to_string()),
                VT_I2 => Some(inner.Anonymous.iVal.to_string()),
                VT_UI2 => Some(inner.Anonymous.uiVal.to_string()),
                VT_UI1 => Some(inner.Anonymous.bVal.to_string()),
                VT_BOOL => Some((inner.Anonymous.boolVal.0 != 0).to_string()),
                _ => None,
            }
        };
        // SAFETY: `value` was filled by `Get` and is cleared exactly once.
        let _ = unsafe { VariantClear(&raw mut value) };
        out
    };
    let mut objects = Vec::new();
    while objects.len() < MAX_OBJECTS {
        let mut slot = [None];
        let mut returned = 0_u32;
        // SAFETY: one output slot and a counter this loop owns.
        let hr = unsafe { rows.Next(WBEM_INFINITE, &mut slot, &raw mut returned) };
        if hr.is_err() {
            return Err(classify(hr.0.cast_unsigned(), "Next")
                .unwrap_or_else(|| SourceError::Failed("Next".to_owned())));
        }
        let Some(object) = slot[0].take().filter(|_| returned == 1) else {
            break;
        };
        let Some(class_name) = read(&object, "__CLASS") else {
            continue;
        };
        let mut found = WmiObject {
            class: class_name,
            properties: std::collections::BTreeMap::new(),
        };
        for name in properties {
            if let Some(v) = read(&object, name) {
                let (v, _) = bope_host::bound_text(v, bope_host::MAX_WMI_PROPERTY_BYTES);
                found.properties.insert(name.clone(), v);
            }
        }
        objects.push(found);
    }
    Ok(Some(objects))
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn query(
    _namespace: &str,
    _class: WmiSubscriptionClass,
    _properties: &[String],
) -> Result<Option<Vec<WmiObject>>, SourceError> {
    Err(SourceError::Unsupported(
        "no WMI on this platform".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_namespace_is_nothing_and_denial_is_access_denied() {
        assert!(classify(WBEM_E_INVALID_NAMESPACE, "x").is_none());
        assert_eq!(
            classify(WBEM_E_ACCESS_DENIED, "x"),
            Some(SourceError::AccessDenied)
        );
        assert!(matches!(
            classify(0x8004_1001, "x"),
            Some(SourceError::Failed(_))
        ));
    }
}
