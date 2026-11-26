//! Registration, login and device-key payloads (spec §4.1–§4.7).
//!
//! The types are defined in [`crate::wire`]; this path is kept for
//! existing users.

pub use crate::wire::{
    BOOTSTRAP_TOKEN_TYPE, BootstrapResponse, DeviceKeyCreated, DeviceKeyInfo,
    DeviceKeyRegistration, DeviceKeysResponse, ED25519, LoginRequest, MAX_PASSWORD_LEN,
    MIN_PASSWORD_LEN, PublicKey, RegistrationMode, RegistrationRequest, UserKeysResponse,
};
