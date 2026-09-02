use std::{env, process::ExitCode};
use yubihsm_qualification::{
    ConnectorHttpTransport, Credentials, FrameTransport, InProcessTransport, Profile,
    cleanup_qualification_objects, replace_public_discovery_credential, run,
};

mod credentials;

const USAGE: &str = "\
Usage:
  yubihsm-qualification core [smoke|managed|extensions|ephemeral]
  yubihsm-qualification connector URL SERIAL [smoke|managed|extensions]
  yubihsm-qualification provision-discovery URL SERIAL
  yubihsm-qualification cleanup URL SERIAL

Managed connector qualification uses one of these credential sources:
  YUBIHSM_QUALIFICATION_HSMAUTH_LABEL and YUBIHSM_QUALIFICATION_HSMAUTH_PASSWORD
  YUBIHSM_QUALIFICATION_PLATFORM_CREDENTIAL
  YUBIHSM_QUALIFICATION_PASSWORD (direct symmetric authentication)
The optional YUBIHSM_QUALIFICATION_AUTH_KEY_ID defaults to 1. The ephemeral profile is
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
    if let [operation, url, serial] = arguments.as_slice()
        && operation == "provision-discovery"
    {
        let mut transport =
            ConnectorHttpTransport::new(url, serial).map_err(|error| error.to_string())?;
        let credentials = credentials::connector_credentials(authentication_key_id()?)?;
        replace_public_discovery_credential(&mut transport, &credentials)?;
        println!(
            "provisioned restricted public discovery credential on {}",
            transport.description()
        );
        return Ok(());
    }
    if let [operation, url, serial] = arguments.as_slice()
        && operation == "cleanup"
    {
        let mut transport =
            ConnectorHttpTransport::new(url, serial).map_err(|error| error.to_string())?;
        let credentials = credentials::connector_credentials(authentication_key_id()?)?;
        let report = cleanup_qualification_objects(&mut transport, &credentials)?;
        println!(
            "removed {} temporary qualification object(s) from {}; {} object(s) remain",
            report.removed,
            transport.description(),
            report.remaining
        );
        return Ok(());
    }
    let (mut transport, profile, core_target): (Box<dyn FrameTransport>, Profile, bool) =
        match arguments.as_slice() {
            [target] if target == "core" => (
                Box::new(InProcessTransport::factory_default()),
                Profile::Ephemeral,
                true,
            ),
            [target, profile] if target == "core" => (
                Box::new(InProcessTransport::factory_default()),
                parse_profile(profile, true)?,
                true,
            ),
            [target, url, serial] if target == "connector" => (
                Box::new(
                    ConnectorHttpTransport::new(url, serial).map_err(|error| error.to_string())?,
                ),
                Profile::Smoke,
                false,
            ),
            [target, url, serial, profile] if target == "connector" => {
                let profile = parse_profile(profile, false)?;
                (
                    Box::new(
                        ConnectorHttpTransport::new(url, serial)
                            .map_err(|error| error.to_string())?,
                    ),
                    profile,
                    false,
                )
            }
            _ => return Err(USAGE.to_owned()),
        };

    let credentials = match profile {
        Profile::Smoke => None,
        Profile::Ephemeral => Some(Credentials::from_password(1, b"password")),
        Profile::Managed | Profile::Extensions if core_target => {
            Some(Credentials::from_password(1, b"password"))
        }
        Profile::Managed | Profile::Extensions => {
            Some(credentials::connector_credentials(authentication_key_id()?)?)
        }
    };
    let report =
        run(&mut *transport, profile, credentials.as_ref()).map_err(|error| error.to_string())?;
    println!(
        "qualified {} (serial {})",
        report.target, report.identity.serial
    );
    for case in report.passed {
        println!("  PASS {case}");
    }
    for case in report.unsupported {
        println!("  UNSUPPORTED {case}");
    }
    Ok(())
}

fn authentication_key_id() -> Result<u16, String> {
    env::var("YUBIHSM_QUALIFICATION_AUTH_KEY_ID")
        .ok()
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|_| "YUBIHSM_QUALIFICATION_AUTH_KEY_ID must be a u16".to_owned())
        })
        .transpose()
        .map(|value| value.unwrap_or(1))
}

fn parse_profile(value: &str, core: bool) -> Result<Profile, String> {
    match value {
        "smoke" => Ok(Profile::Smoke),
        "managed" => Ok(Profile::Managed),
        "extensions" => Ok(Profile::Extensions),
        "ephemeral" if core => Ok(Profile::Ephemeral),
        "ephemeral" => Err(
            "the ephemeral profile is limited to a fresh in-process core; use managed for a connector"
                .to_owned(),
        ),
        _ => Err(USAGE.to_owned()),
    }
}
