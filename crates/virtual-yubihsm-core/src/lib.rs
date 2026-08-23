//! Transport-neutral YubiHSM 2 compatible device behavior.
//!
//! USB, HTTP, and process-lifecycle concerns intentionally live outside this
//! crate. The core accepts and returns YubiHSM protocol frames and owns the
//! device's sessions, authorization policy, objects, audit state, and options.

mod authorization;
mod capability;
mod device;
mod error;
mod frame;
mod object;
mod protocol;
mod secure_channel_crypto;
mod session;

pub use authorization::SessionAuthorization;
pub use capability::{Capability, CapabilitySet};
pub use device::{Device, DeviceConfig};
pub use error::{DeviceError, Result};
pub use frame::Frame;
pub use object::{
    AuthenticationKeyMaterial, ObjectInfo, ObjectKey, ObjectMaterial, ObjectRecord, ObjectType,
};
pub use protocol::CommandCode;
