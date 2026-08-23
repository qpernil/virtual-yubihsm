//! Unprivileged YubiHSM 2 protocol worker for `usb-gadget-supervisor`.

#[cfg(any(target_os = "linux", test))]
mod functionfs;
#[cfg(any(target_os = "linux", test))]
mod usb_identity;
#[cfg(any(target_os = "linux", test))]
mod worker_protocol;

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{env, io};

#[cfg(target_os = "linux")]
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

fn main() {
    if let Err(error) = run() {
        eprintln!("virtual-yubihsm-worker: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let Some(serial) = parse_arguments(env::args().skip(1))? else {
        return Ok(());
    };

    #[cfg(target_os = "linux")]
    {
        install_signal_handlers()?;
        functionfs::run_worker(serial, &STOP_REQUESTED)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = serial;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the virtual YubiHSM worker is Linux-only",
        ))
    }
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> io::Result<Option<u32>> {
    let mut serial = 12_345_678;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                println!(
                    "Usage: virtual-yubihsm-worker [--serial DECIMAL]\n\n\
                     Unprivileged YubiHSM 2 FunctionFS worker for usb-gadget-supervisor.\n\
                     Persistent state is stored in STATE_DIRECTORY."
                );
                return Ok(None);
            }
            "--serial" => {
                let value = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--serial needs a value")
                })?;
                serial = value.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid decimal serial number")
                })?;
                if serial == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "serial number must be nonzero",
                    ));
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument {argument}"),
                ));
            }
        }
    }
    Ok(Some(serial))
}

#[cfg(target_os = "linux")]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_serial_and_rejects_unknown_arguments() {
        assert_eq!(
            parse_arguments(["--serial".to_owned(), "42".to_owned()]).unwrap(),
            Some(42)
        );
        assert!(parse_arguments(["--unknown".to_owned()]).is_err());
    }
}
