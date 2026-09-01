use std::{env, process::ExitCode};
use yubihsm_qualification::{
    ConnectorHttpTransport, Credentials, FrameTransport, InProcessTransport, Profile, run,
};

const USAGE: &str = "\
Usage:
  yubihsm-qualification core [smoke|managed|ephemeral]
  yubihsm-qualification connector URL SERIAL [smoke|managed]

Managed connector qualification reads the password from
YUBIHSM_QUALIFICATION_PASSWORD and the optional Authentication Key ID from
YUBIHSM_QUALIFICATION_AUTH_KEY_ID (default 1). The ephemeral profile is
intentionally limited to a fresh in-process core because it changes audit
configuration and leaves audit entries behind.";

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let (mut transport, profile): (Box<dyn FrameTransport>, Profile) = match arguments.as_slice() {
        [target] if target == "core" => (
            Box::new(InProcessTransport::factory_default()),
            Profile::Ephemeral,
        ),
        [target, profile] if target == "core" => (
            Box::new(InProcessTransport::factory_default()),
            parse_profile(profile, true)?,
        ),
        [target, url, serial] if target == "connector" => (
            Box::new(ConnectorHttpTransport::new(url, serial).map_err(|error| error.to_string())?),
            Profile::Smoke,
        ),
        [target, url, serial, profile] if target == "connector" => {
            let profile = parse_profile(profile, false)?;
            (
                Box::new(
                    ConnectorHttpTransport::new(url, serial).map_err(|error| error.to_string())?,
                ),
                profile,
            )
        }
        _ => return Err(USAGE.to_owned()),
    };

    let credentials = match profile {
        Profile::Smoke => None,
        Profile::Ephemeral => Some(Credentials::from_password(1, b"password")),
        Profile::Managed => {
            let password = env::var("YUBIHSM_QUALIFICATION_PASSWORD").map_err(|_| {
                "managed qualification requires YUBIHSM_QUALIFICATION_PASSWORD".to_owned()
            })?;
            let authentication_key_id = env::var("YUBIHSM_QUALIFICATION_AUTH_KEY_ID")
                .ok()
                .map(|value| {
                    value
                        .parse::<u16>()
                        .map_err(|_| "YUBIHSM_QUALIFICATION_AUTH_KEY_ID must be a u16".to_owned())
                })
                .transpose()?
                .unwrap_or(1);
            Some(Credentials::from_password(
                authentication_key_id,
                password.as_bytes(),
            ))
        }
    };
    let report =
        run(&mut *transport, profile, credentials.as_ref()).map_err(|error| error.to_string())?;
    println!(
        "qualified {} (serial {}, firmware {}.{}.{})",
        report.target,
        report.identity.serial,
        report.identity.version[0],
        report.identity.version[1],
        report.identity.version[2]
    );
    for case in report.passed {
        println!("  PASS {case}");
    }
    Ok(())
}

fn parse_profile(value: &str, core: bool) -> Result<Profile, String> {
    match value {
        "smoke" => Ok(Profile::Smoke),
        "managed" => Ok(Profile::Managed),
        "ephemeral" if core => Ok(Profile::Ephemeral),
        "ephemeral" => Err(
            "the ephemeral profile is limited to a fresh in-process core; use managed for a connector"
                .to_owned(),
        ),
        _ => Err(USAGE.to_owned()),
    }
}
