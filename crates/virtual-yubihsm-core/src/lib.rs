//! Transport-neutral YubiHSM 2 compatible device behavior.
//!
//! USB, HTTP, and process-lifecycle concerns intentionally live outside this
//! crate. The core accepts and returns YubiHSM protocol frames and owns the
//! device's sessions, authorization policy, objects, audit state, and options.
//! The optional `persistent-runtime` feature adds the common durable device
//! owner used by transport frontends while leaving transport I/O outside.

mod algorithm;
mod authorization;
mod capability;
mod device;
mod error;
mod firmware;
mod frame;
mod object;
#[cfg(all(feature = "persistent-runtime", unix))]
mod persistent_runtime;
mod protocol;
mod request;
mod secure_channel_crypto;
mod session;
mod session_object;
mod wire;

pub use algorithm::Algorithm;
pub use authorization::SessionAuthorization;
pub use capability::{Capability, CapabilitySet};
pub use device::{Device, DeviceConfig};
pub use error::{DeviceError, Result};
pub use firmware::FirmwareProfile;
pub use frame::{Frame, MAX_FRAME_LENGTH};
pub use object::{
    AuthenticationKeyMaterial, ObjectInfo, ObjectKey, ObjectMaterial, ObjectRecord, ObjectType,
};
#[cfg(all(feature = "persistent-runtime", unix))]
pub use persistent_runtime::{PersistenceMode, PersistentDevice, PersistentDeviceHandle};
pub use protocol::{CommandCode, SessionObjectCommand};
