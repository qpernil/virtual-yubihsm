use crate::{Options, Persistence};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use virtual_yubihsm_core::{
    DeviceConfig, MAX_FRAME_LENGTH, PersistenceMode, PersistentDevice, PersistentDeviceHandle,
};

const O_NONBLOCK: i32 = 0x800;
const BSC_TARGET_IOC_GET_INFO: libc::c_ulong = 0x8020_4200;
const PERSISTENCE_BATCH_DELAY: Duration = Duration::from_millis(500);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

pub(super) fn run(options: Options) -> io::Result<()> {
    // Claim FD 3 before state-file opens could reuse an absent inherited descriptor.
    let mut target = open_target(&options)?;
    install_signal_handlers()?;
    validate_state_directory(&options.state_directory)?;
    let config = DeviceConfig {
        serial: options.serial,
        ..DeviceConfig::default()
    };
    validate_target(&target)?;
    let persistence_mode = match options.persistence {
        Persistence::Batched => PersistenceMode::Batched(PERSISTENCE_BATCH_DELAY),
        Persistence::Immediate => PersistenceMode::Immediate,
    };
    let runtime =
        PersistentDevice::open(config, &options.state_directory, persistence_mode, || {
            STOP_REQUESTED.store(true, Ordering::Relaxed)
        })?;
    let hsm = runtime.handle();
    eprintln!(
        "virtual-yubihsm-i2c: serving serial {} on {}; state {}",
        options.serial,
        if options.inherited_device {
            "inherited FD 3".into()
        } else {
            options.device.display().to_string()
        },
        runtime.state_path().display()
    );

    let result = serve(&mut target, &hsm);
    let persistence_result = runtime.shutdown();
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

fn serve(target: &mut File, hsm: &PersistentDeviceHandle) -> io::Result<()> {
    let mut request = vec![0_u8; MAX_FRAME_LENGTH];
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
        let response = hsm.execute(&request[..length])?;
        queue_response(target, &response)?;
        eprintln!(
            "virtual-yubihsm-i2c: command {command:#04x}, request {length} bytes, response {} bytes",
            response.len()
        );
    }
    Ok(())
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
    validate_target_info(&info)
}

fn validate_target_info(info: &[u32; 8]) -> io::Result<()> {
    if info[0] != 3 || info[5] != 1 {
        return Err(io::Error::other(
            "I2C target requires driver ABI 3 with a configured READY GPIO",
        ));
    }
    if usize::try_from(info[3]).unwrap_or_default() < MAX_FRAME_LENGTH {
        return Err(io::Error::other(format!(
            "I2C target supports {}-byte transfers; at least {MAX_FRAME_LENGTH} bytes are required",
            info[3]
        )));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_info_requires_ready_abi_and_full_frame_capacity() {
        let mut info = [0_u32; 8];
        info[0] = 3;
        info[3] = MAX_FRAME_LENGTH as u32;
        info[5] = 1;
        assert!(validate_target_info(&info).is_ok());

        info[3] = MAX_FRAME_LENGTH as u32 - 1;
        assert!(validate_target_info(&info).is_err());

        info[3] = MAX_FRAME_LENGTH as u32;
        info[5] = 0;
        assert!(validate_target_info(&info).is_err());
    }
}
