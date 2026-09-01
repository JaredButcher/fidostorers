//! Passive discovery of connected FIDO authenticators.
//!
//! This is deliberately *not* built on the `authenticator` crate: that crate
//! exposes no public enumeration API, and its device discovery is entangled with
//! actually running an operation (which needs a user touch). Listing should be a
//! read-only, no-touch, no-prompt operation, so it is implemented directly against
//! the platform's HID device database.
//!
//! Devices are identified as FIDO authenticators by the FIDO HID usage page
//! (`0xF1D0`, usage `0x01`), which is how the CTAP HID spec says to find them.
//!
//! What this deliberately does *not* do is open the device for I/O to ask it
//! whether it supports `hmac-secret` (a CTAP2 `getInfo` call). Doing so would fail
//! on non-elevated Windows, and would risk disturbing a device mid-operation. So
//! [`DeviceInfo::supports_hmac_secret`](crate::DeviceInfo::supports_hmac_secret)
//! and its sibling are `None` here; the authoritative answer comes from actually
//! running `register`/`derive`.

use crate::{DeviceInfo, TokenError};

/// The FIDO alliance's HID usage page, from the CTAP HID spec.
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
pub(crate) const FIDO_USAGE_PAGE: u16 = 0xF1D0;
/// Usage `U2FHID` within [`FIDO_USAGE_PAGE`].
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
pub(crate) const FIDO_USAGE_U2FHID: u16 = 0x01;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as imp;

#[cfg(not(any(target_os = "linux", windows)))]
mod unsupported;
#[cfg(not(any(target_os = "linux", windows)))]
use unsupported as imp;

/// Enumerate connected FIDO authenticators.
///
/// Returns an empty vector (not an error) when nothing is plugged in — "no devices"
/// is a normal state for a listing, whereas [`TokenError::NoDevice`] is reserved for
/// operations that genuinely needed one.
pub fn list_devices() -> Result<Vec<DeviceInfo>, TokenError> {
    let devices = imp::list_devices()?;
    log::debug!("enumerated {} FIDO HID device(s)", devices.len());
    for device in &devices {
        log::debug!(
            "  {} vid={:04x?} pid={:04x?} product={:?} manufacturer={:?}",
            device.path,
            device.vendor_id,
            device.product_id,
            device.product,
            device.manufacturer
        );
    }
    Ok(devices)
}
