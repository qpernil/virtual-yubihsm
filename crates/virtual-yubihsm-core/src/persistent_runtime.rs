//! Shared persistent device ownership for transport frontends.

use crate::{Device, DeviceConfig, Frame, SessionAuthorization};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
pub use usb_gadget_worker::PersistenceMode;
use usb_gadget_worker::{
    StateLock, StatePersistence, StatePersistenceHandle, replace_file_atomically,
};

/// Owns one durable virtual YubiHSM and its exclusive state lock.
///
/// Frontends remain responsible for validating or creating the state directory
/// before opening the device. The runtime owns the lock from before restoration
/// until after the final persistence flush.
pub struct PersistentDevice {
    persistence: StatePersistence<Device>,
    _state_lock: StateLock,
    state_path: PathBuf,
    version: [u8; 3],
}

/// Cloneable command handle for a [`PersistentDevice`].
#[derive(Clone)]
pub struct PersistentDeviceHandle {
    persistence: StatePersistenceHandle<Device>,
}

impl PersistentDevice {
    pub fn open<F>(
        config: DeviceConfig,
        state_directory: &Path,
        mode: PersistenceMode,
        on_failure: F,
    ) -> io::Result<Self>
    where
        F: Fn() + Send + 'static,
    {
        let state_path = state_directory.join(format!("yubihsm-{}.cbor", config.serial));
        let state_lock =
            StateLock::acquire(state_directory.join(format!("yubihsm-{}.lock", config.serial)))?;
        let version = config.version;
        let device = load_or_create_state(config, &state_path)?;
        let persistence =
            StatePersistence::start(device, state_path.clone(), mode, encode_state, on_failure)?;
        Ok(Self {
            persistence,
            _state_lock: state_lock,
            state_path,
            version,
        })
    }

    pub fn handle(&self) -> PersistentDeviceHandle {
        PersistentDeviceHandle {
            persistence: self.persistence.handle(),
        }
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub fn version(&self) -> [u8; 3] {
        self.version
    }

    pub fn flush(&self) -> io::Result<()> {
        self.persistence.flush()
    }

    pub fn shutdown(self) -> io::Result<()> {
        let Self {
            persistence,
            _state_lock,
            state_path: _,
            version: _,
        } = self;
        let result = persistence.shutdown();
        drop(_state_lock);
        result
    }
}

impl PersistentDeviceHandle {
    pub fn execute(&self, encoded: &[u8]) -> io::Result<Vec<u8>> {
        self.execute_observing(encoded, |_, _, _| {})
    }

    pub fn execute_observing<O>(&self, encoded: &[u8], observer: O) -> io::Result<Vec<u8>>
    where
        O: FnMut(SessionAuthorization, &Frame, &Frame),
    {
        self.persistence.check_health()?;
        let (response, mutation) = {
            let mut device = self
                .persistence
                .state()
                .lock()
                .map_err(|_| io::Error::other("virtual YubiHSM state lock poisoned"))?;
            let response = device.handle_encoded_observing(encoded, observer);
            let mutation = device
                .take_persistent_change()
                .map_err(|error| {
                    io::Error::other(format!("advance persistent YubiHSM state epoch: {error}"))
                })?
                .then(|| self.persistence.record_mutation())
                .transpose()?;
            (response, mutation)
        };
        match mutation {
            Some(mutation) => mutation.wait()?,
            None => self.persistence.check_health()?,
        }
        Ok(response)
    }

    pub fn clear_sessions(&self) -> io::Result<()> {
        self.persistence
            .state()
            .lock()
            .map_err(|_| io::Error::other("virtual YubiHSM state lock poisoned"))?
            .clear_sessions();
        Ok(())
    }
}

fn load_or_create_state(config: DeviceConfig, path: &Path) -> io::Result<Device> {
    match fs::read(path) {
        Ok(encoded) => Device::from_persistent_state(config, &encoded).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("load persistent YubiHSM state {}: {error}", path.display()),
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let device = Device::factory_default(config);
            replace_file_atomically(path, &encode_state(&device)?)?;
            Ok(device)
        }
        Err(error) => Err(with_path(error, "read persistent YubiHSM state", path)),
    }
}

fn encode_state(device: &Device) -> io::Result<Vec<u8>> {
    device
        .persistent_state()
        .map_err(|error| io::Error::other(format!("encode persistent YubiHSM state: {error}")))
}

fn with_path(error: io::Error, operation: &str, path: &Path) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} {}: {error}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommandCode, Frame};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "virtual-yubihsm-persistent-runtime-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        directory
    }

    #[test]
    fn runtime_owns_state_executes_frames_and_releases_the_lock() {
        let directory = temporary_directory();
        let config = DeviceConfig {
            serial: 12_345_678,
            ..DeviceConfig::default()
        };
        let runtime = PersistentDevice::open(
            config.clone(),
            &directory,
            PersistenceMode::Immediate,
            || {},
        )
        .unwrap();
        assert_eq!(runtime.version(), config.version);
        assert!(runtime.state_path().exists());
        let second_error = match PersistentDevice::open(
            config.clone(),
            &directory,
            PersistenceMode::Immediate,
            || {},
        ) {
            Ok(runtime) => {
                runtime.shutdown().unwrap();
                panic!("second runtime unexpectedly acquired persistent state")
            }
            Err(error) => error,
        };
        assert!(second_error.to_string().contains("persistent state lock"));

        let request = Frame::new(CommandCode::GetDeviceInfo as u8, Vec::new())
            .unwrap()
            .encode();
        let response = Frame::parse(&runtime.handle().execute(&request).unwrap()).unwrap();
        assert_eq!(response.command, CommandCode::GetDeviceInfo as u8 | 0x80);
        runtime.handle().clear_sessions().unwrap();
        runtime.shutdown().unwrap();

        PersistentDevice::open(config, &directory, PersistenceMode::Immediate, || {})
            .unwrap()
            .shutdown()
            .unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn corrupt_state_fails_closed_without_replacement() {
        let directory = temporary_directory();
        let config = DeviceConfig::default();
        let path = directory.join(format!("yubihsm-{}.cbor", config.serial));
        fs::write(&path, b"corrupt").unwrap();
        let error =
            match PersistentDevice::open(config, &directory, PersistenceMode::Immediate, || {}) {
                Ok(runtime) => {
                    runtime.shutdown().unwrap();
                    panic!("corrupt state unexpectedly opened")
                }
                Err(error) => error,
            };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(path).unwrap(), b"corrupt");
        fs::remove_dir_all(directory).unwrap();
    }
}
