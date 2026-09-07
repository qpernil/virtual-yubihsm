//! Unprivileged I2C target frontend for `virtual-yubihsm-core`.

use std::{env, io, path::PathBuf};

#[cfg(target_os = "linux")]
mod linux;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Options {
    serial: u32,
    state_directory: PathBuf,
    device: PathBuf,
    inherited_device: bool,
    persistence: Persistence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Persistence {
    Batched,
    Immediate,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("virtual-yubihsm-i2c: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let Some(options) = parse_arguments(env::args().skip(1))? else {
        return Ok(());
    };

    #[cfg(target_os = "linux")]
    {
        linux::run(options)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the I2C target frontend is Linux-only",
        ))
    }
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> io::Result<Option<Options>> {
    let mut serial = None;
    let mut state_directory = None;
    let mut device = PathBuf::from("/dev/bsc-target0");
    let mut persistence = Persistence::Batched;
    let mut inherited_device = false;
    let mut explicit_device = false;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                println!(
                    "Usage: virtual-yubihsm-i2c --serial DECIMAL --state-directory PATH [--device PATH | --inherited-device] [--persistence MODE]\n\n\
                     Serve one real virtual YubiHSM protocol endpoint through the BSC I2C\n\
                     target driver. The kernel module and overlay must already be loaded.\n\
                     The process needs read/write access to DEVICE, but does not require root.\n\
                     --inherited-device takes ownership of an already-open device on FD 3.\n\
                     MODE is batched (default, 500 ms) or immediate."
                );
                return Ok(None);
            }
            "--serial" => {
                let value = required_value(&mut arguments, "--serial")?;
                let parsed = value.parse::<u32>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid decimal serial number")
                })?;
                if parsed == 0 {
                    return invalid("serial number must be nonzero");
                }
                serial = Some(parsed);
            }
            "--state-directory" => {
                state_directory = Some(PathBuf::from(required_value(
                    &mut arguments,
                    "--state-directory",
                )?));
            }
            "--inherited-device" => inherited_device = true,
            "--device" => {
                explicit_device = true;
                device = PathBuf::from(required_value(&mut arguments, "--device")?);
            }
            "--persistence" => {
                persistence = parse_persistence(&required_value(&mut arguments, "--persistence")?)?;
            }
            value if value.starts_with("--persistence=") => {
                persistence = parse_persistence(&value["--persistence=".len()..])?;
            }
            _ => return invalid(format!("unknown argument {argument}")),
        }
    }

    let serial = serial
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--serial is required"))?;
    let state_directory = state_directory.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "--state-directory is required")
    })?;
    if !state_directory.is_absolute() {
        return invalid("--state-directory must be an absolute path");
    }
    if inherited_device && explicit_device {
        return invalid("--device and --inherited-device are mutually exclusive");
    }
    if !device.is_absolute() {
        return invalid("--device must be an absolute path");
    }
    Ok(Some(Options {
        serial,
        state_directory,
        device,
        inherited_device,
        persistence,
    }))
}

fn parse_persistence(value: &str) -> io::Result<Persistence> {
    match value {
        "batched" => Ok(Persistence::Batched),
        "immediate" => Ok(Persistence::Immediate),
        _ => invalid(format!(
            "invalid persistence mode {value:?}; use batched or immediate"
        )),
    }
}

fn required_value(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> io::Result<String> {
    arguments.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{option} needs a value"),
        )
    })
}

fn invalid<T>(message: impl Into<String>) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> io::Result<Option<Options>> {
        parse_arguments(arguments.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn parses_required_options_and_device_override() {
        assert_eq!(
            parse(&[
                "--serial",
                "12345678",
                "--state-directory",
                "/var/lib/virtual-yubihsm-i2c/one",
                "--device",
                "/dev/test-target",
            ])
            .unwrap(),
            Some(Options {
                serial: 12_345_678,
                state_directory: PathBuf::from("/var/lib/virtual-yubihsm-i2c/one"),
                device: PathBuf::from("/dev/test-target"),
                inherited_device: false,
                persistence: Persistence::Batched,
            })
        );
    }

    #[test]
    fn inherited_device_excludes_a_device_path() {
        let base = [
            "--serial",
            "1",
            "--state-directory",
            "/state",
            "--inherited-device",
        ];
        assert!(parse(&base).unwrap().unwrap().inherited_device);
        let mut both = base.to_vec();
        both.extend(["--device", "/dev/bsc-target0"]);
        assert!(parse(&both).is_err());
    }

    #[test]
    fn parses_immediate_persistence() {
        assert_eq!(
            parse(&[
                "--serial",
                "1",
                "--state-directory",
                "/state",
                "--persistence=immediate",
            ])
            .unwrap()
            .unwrap()
            .persistence,
            Persistence::Immediate
        );
    }

    #[test]
    fn requires_nonzero_serial_and_absolute_paths() {
        assert!(parse(&["--state-directory", "/state"]).is_err());
        assert!(parse(&["--serial", "0", "--state-directory", "/state"]).is_err());
        assert!(parse(&["--serial", "1", "--state-directory", "state"]).is_err());
        assert!(
            parse(&[
                "--serial",
                "1",
                "--state-directory",
                "/state",
                "--device",
                "target",
            ])
            .is_err()
        );
    }
}
