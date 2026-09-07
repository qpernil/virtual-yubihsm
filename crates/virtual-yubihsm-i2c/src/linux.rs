use crate::{Options, Persistence};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use usb_gadget_worker::{
    PersistenceMode, StateLock, StatePersistence, StatePersistenceHandle, replace_file_atomically,
};
use virtual_yubihsm_core::{Device, DeviceConfig};

const MAX_TRANSFER: usize = 8_192;
const O_NONBLOCK: i32 = 0x800;
const BSC_TARGET_IOC_GET_INFO: libc::c_ulong = 0x8020_4200;
const PERSISTENCE_BATCH_DELAY: Duration = Duration::from_millis(500);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

pub(super) fn run(options: Options) -> io::Result<()> {
    // Claim FD 3 before state-file opens could reuse an absent inherited descriptor.
    let mut target = open_target(&options)?;
    install_signal_handlers()?;
    validate_state_directory(&options.state_directory)?;
    let state_path = options
        .state_directory
        .join(format!("yubihsm-{}.cbor", options.serial));
    let _state_lock = StateLock::acquire(
        options
            .state_directory
            .join(format!("yubihsm-{}.lock", options.serial)),
    )?;
    let config = DeviceConfig {
        serial: options.serial,
        ..DeviceConfig::default()
    };
    let hsm = load_or_create_state(config, &state_path)?;
    validate_target(&target)?;
    let persistence_mode = match options.persistence {
        Persistence::Batched => PersistenceMode::Batched(PERSISTENCE_BATCH_DELAY),
        Persistence::Immediate => PersistenceMode::Immediate,
    };
    let persistence = StatePersistence::start(
        hsm,
        state_path.clone(),
        persistence_mode,
        encode_state,
        || STOP_REQUESTED.store(true, Ordering::Relaxed),
    )?;
    let hsm = persistence.handle();
    eprintln!(
        "virtual-yubihsm-i2c: serving serial {} on {}; state {}",
        options.serial,
        if options.inherited_device {
            "inherited FD 3".into()
        } else {
            options.device.display().to_string()
        },
        state_path.display()
    );

    let result = serve(&mut target, &hsm);
    let persistence_result = persistence.shutdown();
    result.and(persistence_result)
}

fn open_target(options: &Options) -> io::Result<File> {
    if !options.inherited_device {
        return OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_NONBLOCK)
            .open(&options.device)
            .map_err(|error| with_path(error, "open I2C target", &options.device));
    }
    // SAFETY: fcntl validates the inherited descriptor before ownership is taken.
    let flags = unsafe { libc::fcntl(3, libc::F_GETFL) };
    if flags < 0 {
        return Err(with_context(
            io::Error::last_os_error(),
            "inherit I2C target on FD 3",
        ));
    }
    // SAFETY: FD 3 is the launcher's transferred device, owned only here.
    let target = unsafe { File::from_raw_fd(3) };
    if flags & libc::O_ACCMODE != libc::O_RDWR {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "FD 3 must be read/write",
        ));
    }
    // SAFETY: target owns this valid descriptor. Prevent further inheritance and
    // preserve existing flags while enabling the frontend's nonblocking I/O.
    if unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(3, libc::F_SETFL, flags | O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(target)
}

fn serve(target: &mut File, hsm: &StatePersistenceHandle<Device>) -> io::Result<()> {
    let mut request = vec![0_u8; MAX_TRANSFER];
    while !STOP_REQUESTED.load(Ordering::Relaxed) {
        let length = match target.read(&mut request) {
            Ok(0) => continue,
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_for_descriptor(target, libc::POLLIN, Duration::from_millis(250))?;
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(with_context(error, "read I2C request")),
        };

        let command = request.first().copied().unwrap_or_default();
        let (response, mutation) = {
            let mut device = lock_device(hsm.state());
            let response = device.handle_encoded(&request[..length]);
            let mutation = if device.take_persistent_change().map_err(|error| {
                io::Error::other(format!("advance persistent YubiHSM state epoch: {error}"))
            })? {
                Some(hsm.record_mutation()?)
            } else {
                None
            };
            (response, mutation)
        };
        if let Some(mutation) = mutation {
            mutation.wait()?;
        } else {
            hsm.check_health()?;
        }
        queue_response(target, &response)?;
        eprintln!(
            "virtual-yubihsm-i2c: command {command:#04x}, request {length} bytes, response {} bytes",
            response.len()
        );
    }
    Ok(())
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
            let hsm = Device::factory_default(config);
            persist(&hsm, path)?;
            Ok(hsm)
        }
        Err(error) => Err(with_path(error, "read persistent YubiHSM state", path)),
    }
}

fn persist(hsm: &Device, path: &Path) -> io::Result<()> {
    let encoded = encode_state(hsm)?;
    replace_file_atomically(path, &encoded)
        .map_err(|error| with_path(error, "replace persistent YubiHSM state", path))
}

fn encode_state(hsm: &Device) -> io::Result<Vec<u8>> {
    hsm.persistent_state()
        .map_err(|error| io::Error::other(format!("encode persistent YubiHSM state: {error}")))
}

fn lock_device(device: &Mutex<Device>) -> MutexGuard<'_, Device> {
    device.lock().unwrap_or_else(|error| error.into_inner())
}

fn validate_state_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata =
        fs::metadata(path).map_err(|error| with_path(error, "inspect state directory", path))?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("state path {} is not a directory", path.display()),
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "state directory {} has mode {mode:04o}; remove all group and other permissions",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn queue_response(target: &mut File, response: &[u8]) -> io::Result<()> {
    loop {
        match target.write(response) {
            Ok(length) if length == response.len() => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short I2C response write",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(with_context(error, "queue I2C response")),
        }
    }
}

fn wait_for_descriptor(file: &File, events: i16, timeout: Duration) -> io::Result<()> {
    let mut descriptor = libc::pollfd {
        fd: file.as_raw_fd(),
        events,
        revents: 0,
    };
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: descriptor points to one initialized pollfd for the duration of poll.
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    } else if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(io::Error::other(format!(
            "I2C target reported poll events {:#x}",
            descriptor.revents
        )));
    }
    Ok(())
}

fn validate_target(target: &File) -> io::Result<()> {
    let mut info = [0_u32; 8];
    // SAFETY: info has the layout of bsc_target_info from the driver UAPI.
    if unsafe {
        libc::ioctl(
            target.as_raw_fd(),
            BSC_TARGET_IOC_GET_INFO,
            info.as_mut_ptr(),
        )
    } < 0
    {
        return Err(with_context(
            io::Error::last_os_error(),
            "query I2C target ABI",
        ));
    }
    if info[0] != 3 || info[5] != 1 {
        return Err(io::Error::other(
            "I2C target requires driver ABI 3 with a configured READY GPIO",
        ));
    }
    Ok(())
}

fn install_signal_handlers() -> io::Result<()> {
    unsafe extern "C" fn stop(_signal: i32) {
        STOP_REQUESTED.store(true, Ordering::Relaxed);
    }
    // SAFETY: stop has the C signal-handler ABI and only stores to an atomic.
    if unsafe { libc::signal(libc::SIGINT, stop as *const () as usize) } == libc::SIG_ERR
        || unsafe { libc::signal(libc::SIGTERM, stop as *const () as usize) } == libc::SIG_ERR
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn with_context(error: io::Error, context: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

fn with_path(error: io::Error, context: &str, path: &Path) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{context} {}: {error}", path.display()),
    )
}
