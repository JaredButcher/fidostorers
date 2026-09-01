//! Fallback for platforms this crate has no enumeration backend for (v1 targets
//! Linux and Windows; see plan/01-crate-fido-token.md "Platform notes").

use crate::{DeviceInfo, TokenError};

pub(super) fn list_devices() -> Result<Vec<DeviceInfo>, TokenError> {
    Err(TokenError::NotImplemented(
        "device enumeration is implemented for Linux and Windows only",
    ))
}
