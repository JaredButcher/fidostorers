//! Windows enumeration via SetupAPI + the HID user-mode library.
//!
//! Walks the HID device interface class, opens each interface with *zero* desired
//! access, and asks `HidP_GetCaps` for its top-level usage. A zero-access open only
//! permits metadata queries (`HidD_*`), never reads or writes, which matters here:
//! Windows 10 1903+ installs a filter that denies read/write opens of FIDO HID
//! devices to non-elevated processes, but leaves the metadata path alone. That is
//! why enumeration works unprivileged while `register`/`derive` may not — see
//! docs/M1-MANUAL-TESTING.md.

use std::ptr;

use winapi::shared::guiddef::GUID;
use winapi::shared::hidpi::{HidP_GetCaps, HIDP_CAPS, HIDP_STATUS_SUCCESS, PHIDP_PREPARSED_DATA};
use winapi::shared::hidsdi::{
    HidD_FreePreparsedData, HidD_GetAttributes, HidD_GetHidGuid, HidD_GetManufacturerString,
    HidD_GetPreparsedData, HidD_GetProductString, HIDD_ATTRIBUTES,
};
use winapi::shared::minwindef::DWORD;
use winapi::shared::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::setupapi::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
    SetupDiGetDeviceInterfaceDetailW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO,
    PSP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVICE_INTERFACE_DATA,
};
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, HANDLE};

use crate::enumerate::{FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID};
use crate::{DeviceInfo, TokenError};

/// Windows string properties are capped well below this; 256 wide chars is what the
/// HID user-mode library's own callers conventionally allocate.
const STRING_BUFFER_WCHARS: usize = 256;

/// Owns an `HDEVINFO` so every early return still destroys it.
struct DeviceInfoSet(HDEVINFO);

impl Drop for DeviceInfoSet {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from SetupDiGetClassDevsW and was checked against
        // INVALID_HANDLE_VALUE, and this runs exactly once.
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

/// Owns a device `HANDLE` from `CreateFileW`.
struct DeviceHandle(HANDLE);

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from CreateFileW and was checked against
        // INVALID_HANDLE_VALUE, and this runs exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

pub(super) fn list_devices() -> Result<Vec<DeviceInfo>, TokenError> {
    // SAFETY: `HidD_GetHidGuid` only writes the GUID it is handed.
    let hid_guid: GUID = unsafe {
        let mut guid = std::mem::zeroed::<GUID>();
        HidD_GetHidGuid(&mut guid);
        guid
    };

    // SAFETY: null enumerator/parent are documented as "all devices of this class".
    let set = unsafe {
        SetupDiGetClassDevsW(
            &hid_guid,
            ptr::null(),
            ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if set == INVALID_HANDLE_VALUE {
        // SAFETY: reads a thread-local error code, no pointers involved.
        let code = unsafe { GetLastError() };
        return Err(TokenError::Transport(format!(
            "SetupDiGetClassDevsW failed (error {code})"
        )));
    }
    let set = DeviceInfoSet(set);

    let mut devices = Vec::new();
    let mut unopenable = 0usize;

    for index in 0.. {
        let mut iface = unsafe { std::mem::zeroed::<SP_DEVICE_INTERFACE_DATA>() };
        iface.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as DWORD;

        // SAFETY: `set.0` is a live device info set and `iface` is a correctly
        // sized, zeroed SP_DEVICE_INTERFACE_DATA.
        let ok = unsafe {
            SetupDiEnumDeviceInterfaces(set.0, ptr::null_mut(), &hid_guid, index, &mut iface)
        };
        if ok == 0 {
            // SAFETY: reads a thread-local error code.
            let code = unsafe { GetLastError() };
            if code != ERROR_NO_MORE_ITEMS {
                log::warn!("SetupDiEnumDeviceInterfaces stopped at index {index} (error {code})");
            }
            break;
        }

        let path = match interface_path(&set, &mut iface) {
            Ok(path) => path,
            Err(err) => {
                log::debug!("interface {index}: skipping, {err}");
                continue;
            }
        };

        match inspect(&path) {
            Ok(Some(device)) => devices.push(device),
            Ok(None) => log::trace!("{path}: not a FIDO device, skipping"),
            Err(err) => {
                unopenable += 1;
                log::debug!("{path}: skipping, {err}");
            }
        }
    }

    if unopenable > 0 {
        log::warn!(
            "{unopenable} HID device(s) could not be queried and were skipped; \
             a FIDO key hidden behind one of them will not appear in this listing"
        );
    }

    devices.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(devices)
}

/// Fetch the `\\?\hid#...` device path for one enumerated interface.
fn interface_path(
    set: &DeviceInfoSet,
    iface: &mut SP_DEVICE_INTERFACE_DATA,
) -> Result<String, String> {
    let mut required: DWORD = 0;

    // First call sizes the buffer; it is expected to fail with
    // ERROR_INSUFFICIENT_BUFFER after writing `required`.
    // SAFETY: passing a null detail buffer with zero size is the documented way to
    // ask for the required size.
    unsafe {
        SetupDiGetDeviceInterfaceDetailW(
            set.0,
            iface,
            ptr::null_mut(),
            0,
            &mut required,
            ptr::null_mut(),
        )
    };
    // SAFETY: reads a thread-local error code.
    let code = unsafe { GetLastError() };
    if code != ERROR_INSUFFICIENT_BUFFER {
        return Err(format!(
            "SetupDiGetDeviceInterfaceDetailW size probe failed (error {code})"
        ));
    }
    if (required as usize) <= std::mem::size_of::<DWORD>() {
        return Err(format!("implausible detail size {required}"));
    }

    // Allocate as u32 so the buffer is DWORD-aligned, which the detail struct
    // requires; a Vec<u8> would only be guaranteed byte-aligned.
    let mut buffer = vec![0u32; (required as usize).div_ceil(4)];
    let detail = buffer.as_mut_ptr() as PSP_DEVICE_INTERFACE_DETAIL_DATA_W;

    // cbSize is the size of the *fixed* part of the struct, not of the buffer.
    // SAFETY: `detail` points at a buffer of at least `required` bytes.
    unsafe {
        ptr::addr_of_mut!((*detail).cbSize).write(std::mem::size_of::<
            winapi::um::setupapi::SP_DEVICE_INTERFACE_DETAIL_DATA_W,
        >() as DWORD);
    }

    // SAFETY: `detail` is a correctly aligned buffer of `required` bytes whose
    // cbSize field has been initialized as documented.
    let ok = unsafe {
        SetupDiGetDeviceInterfaceDetailW(
            set.0,
            iface,
            detail,
            required,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        // SAFETY: reads a thread-local error code.
        let code = unsafe { GetLastError() };
        return Err(format!(
            "SetupDiGetDeviceInterfaceDetailW failed (error {code})"
        ));
    }

    // The path runs from the DevicePath field to the end of the buffer. Use
    // addr_of! because the struct is `repr(packed)` on x86, where taking a
    // reference to the field would be undefined behaviour.
    // SAFETY: `detail` was just populated by SetupAPI.
    let path_ptr = unsafe { ptr::addr_of!((*detail).DevicePath) as *const u16 };
    let capacity_bytes = required as usize - std::mem::size_of::<DWORD>();
    // SAFETY: SetupAPI NUL-terminates DevicePath within the reported size.
    let wide = unsafe { std::slice::from_raw_parts(path_ptr, capacity_bytes / 2) };
    Ok(wide_to_string(wide))
}

/// Open the interface read-only-metadata and decide whether it is a FIDO device.
fn inspect(path: &str) -> Result<Option<DeviceInfo>, String> {
    let wide_path = to_wide_nul(path);

    // Zero desired access: metadata queries only. This is what keeps enumeration
    // working on non-elevated Windows for FIDO devices.
    // SAFETY: `wide_path` is a NUL-terminated wide string that outlives the call.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: reads a thread-local error code.
        let code = unsafe { GetLastError() };
        return Err(format!("CreateFileW failed (error {code})"));
    }
    let handle = DeviceHandle(handle);

    let (usage_page, usage) = capabilities(&handle)?;
    if usage_page != FIDO_USAGE_PAGE || usage != FIDO_USAGE_U2FHID {
        return Ok(None);
    }

    let mut attributes = unsafe { std::mem::zeroed::<HIDD_ATTRIBUTES>() };
    attributes.Size = std::mem::size_of::<HIDD_ATTRIBUTES>() as u32;
    // SAFETY: `handle` is a live HID handle; `attributes` is sized as documented.
    let have_attributes = unsafe { HidD_GetAttributes(handle.0, &mut attributes) } != 0;

    Ok(Some(DeviceInfo {
        path: path.to_string(),
        product: device_string(&handle, HidD_GetProductString),
        manufacturer: device_string(&handle, HidD_GetManufacturerString),
        vendor_id: have_attributes.then_some(attributes.VendorID),
        product_id: have_attributes.then_some(attributes.ProductID),
        supports_hmac_secret: None,
        supports_client_pin: None,
    }))
}

/// Top-level `(usage_page, usage)` for an open HID device.
fn capabilities(handle: &DeviceHandle) -> Result<(u16, u16), String> {
    let mut preparsed: PHIDP_PREPARSED_DATA = ptr::null_mut();
    // SAFETY: `handle` is live; the out-pointer is a local.
    if unsafe { HidD_GetPreparsedData(handle.0, &mut preparsed) } == 0 || preparsed.is_null() {
        return Err("HidD_GetPreparsedData failed".to_string());
    }

    let mut caps = unsafe { std::mem::zeroed::<HIDP_CAPS>() };
    // SAFETY: `preparsed` is non-null and owned by us until freed below.
    let status = unsafe { HidP_GetCaps(preparsed, &mut caps) };
    // SAFETY: frees the buffer obtained above, exactly once.
    unsafe { HidD_FreePreparsedData(preparsed) };

    if status != HIDP_STATUS_SUCCESS {
        return Err(format!("HidP_GetCaps failed (status {status:#x})"));
    }
    Ok((caps.UsagePage, caps.Usage))
}

/// Call one of the `HidD_Get*String` functions, returning `None` when it fails or
/// yields an empty string.
fn device_string(
    handle: &DeviceHandle,
    get: unsafe extern "system" fn(HANDLE, *mut std::ffi::c_void, u32) -> u8,
) -> Option<String> {
    let mut buffer = [0u16; STRING_BUFFER_WCHARS];
    // SAFETY: `handle` is live and the buffer length is passed in bytes, as the
    // HidD_Get*String contract requires.
    let ok = unsafe {
        get(
            handle.0,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            std::mem::size_of_val(&buffer) as u32,
        )
    };
    if ok == 0 {
        return None;
    }
    let value = wide_to_string(&buffer);
    (!value.is_empty()).then_some(value)
}

/// Decode a wide buffer up to its first NUL.
fn wide_to_string(wide: &[u16]) -> String {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

fn to_wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_to_string_stops_at_nul() {
        let wide: Vec<u16> = "ab\0cd".encode_utf16().collect();
        assert_eq!(wide_to_string(&wide), "ab");
    }

    #[test]
    fn wide_to_string_handles_an_unterminated_buffer() {
        let wide: Vec<u16> = "abc".encode_utf16().collect();
        assert_eq!(wide_to_string(&wide), "abc");
    }

    #[test]
    fn wide_to_string_handles_an_empty_buffer() {
        assert_eq!(wide_to_string(&[]), "");
        assert_eq!(wide_to_string(&[0]), "");
    }

    #[test]
    fn to_wide_nul_terminates() {
        assert_eq!(to_wide_nul("hi"), vec![b'h' as u16, b'i' as u16, 0]);
    }

    #[test]
    fn wide_round_trip() {
        let path = r"\\?\hid#vid_1050&pid_0407";
        assert_eq!(wide_to_string(&to_wide_nul(path)), path);
    }
}
