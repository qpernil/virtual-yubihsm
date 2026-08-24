//! Unprivileged YubiHSM 2 protocol worker for `usb-gadget-supervisor`.

#[cfg(target_os = "linux")]
mod buttons;
#[cfg(any(target_os = "linux", test))]
mod display;
#[cfg(target_os = "linux")]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DisplayKind {
    St7789Spi,
    Sh1106Spi,
}

impl DisplayKind {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "st7789-spi" => Ok(Self::St7789Spi),
            "sh1106-spi" => Ok(Self::Sh1106Spi),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid display {value:?}; use st7789-spi or sh1106-spi"),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Options {
    serial: u32,
    display: DisplayKind,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("virtual-yubihsm-worker: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let Some(options) = parse_arguments(env::args().skip(1))? else {
        return Ok(());
    };

    #[cfg(target_os = "linux")]
    {
        install_signal_handlers()?;
        functionfs::run_worker(options.serial, options.display, &STOP_REQUESTED)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the virtual YubiHSM worker is Linux-only",
        ))
    }
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> io::Result<Option<Options>> {
    let mut serial = 12_345_678;
    let mut display = DisplayKind::St7789Spi;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                println!(
                    "Usage: virtual-yubihsm-worker [--serial DECIMAL] [--display BACKEND]\n\n\
                     Unprivileged YubiHSM 2 FunctionFS worker for usb-gadget-supervisor.\n\
                     Persistent state is stored in STATE_DIRECTORY.\n\
                     BACKEND is st7789-spi (default) or sh1106-spi."
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
            "--display" => {
                let value = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--display needs a value")
                })?;
                display = DisplayKind::parse(&value)?;
            }
            value if value.starts_with("--display=") => {
                display = DisplayKind::parse(&value["--display=".len()..])?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument {argument}"),
                ));
            }
        }
    }
    Ok(Some(Options { serial, display }))
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

    const OLED_PROFILE: &str = include_str!("../profiles/virtual-yubihsm-sh1106-spi.toml");

    #[test]
    fn parses_serial_and_rejects_unknown_arguments() {
        assert_eq!(
            parse_arguments(["--serial".to_owned(), "42".to_owned()]).unwrap(),
            Some(Options {
                serial: 42,
                display: DisplayKind::St7789Spi,
            })
        );
        assert!(parse_arguments(["--unknown".to_owned()]).is_err());
    }

    #[test]
    fn parses_oled_display() {
        assert_eq!(
            parse_arguments(["--display=sh1106-spi".to_owned()]).unwrap(),
            Some(Options {
                serial: 12_345_678,
                display: DisplayKind::Sh1106Spi,
            })
        );
    }

    #[test]
    fn oled_profile_selects_sh1106_and_its_two_control_lines() {
        assert!(OLED_PROFILE.contains("--display=sh1106-spi"));
        assert!(OLED_PROFILE.contains("offsets = [24, 25]"));
    }
}
