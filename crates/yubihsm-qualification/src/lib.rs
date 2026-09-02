//! Transport-independent YubiHSM protocol qualification.
//!
//! Scenarios exchange complete, encoded YubiHSM frames through [`FrameTransport`].
//! The same expectations can therefore exercise the in-process virtual core, a
//! connector-hosted embedded core, a USB-gadget instance, or physical hardware.

use der::Decode;
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
use software_key_core::{
    digest::{HashAlgorithm, hmac},
    secure_channel::{
        pad_iso7816, scp03_cryptogram, scp03_key, unpad_iso7816, x963_kdf_sha256,
        yubico_password_kdf,
    },
    software_key_agreement::{MontgomeryCurve, SoftwareMontgomeryKey},
    software_signing::{
        EcCurve, EdwardsCurve, SignatureScheme, SoftwarePublicKey, ecdsa_signature_from_der,
    },
    software_symmetric::{
        AES_BLOCK_SIZE, aes_cmac, decrypt_aes_cbc, encrypt_aes_block, encrypt_aes_cbc,
    },
};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};
use virtual_yubihsm_core::{
    Algorithm, Capability, CapabilitySet, CommandCode, Device, DeviceConfig, DeviceError, Frame,
    ObjectType,
};
use x509_cert::Certificate;
use zeroize::Zeroizing;

const RESPONSE_BIT: u8 = 0x80;
const ERROR_COMMAND: u8 = 0x7f;
const MAC_LENGTH: usize = 8;
const CHALLENGE_LENGTH: usize = 8;
const AUTHENTICATION_ALGORITHM_AES128_YUBICO: u8 = Algorithm::Aes128YubicoAuthentication as u8;
const OPTION_COMMAND_AUDIT: u8 = 0x03;
const OPTION_FORCE_AUDIT: u8 = 0x01;
const OPTION_ON: u8 = 1;

/// A transport capable of exchanging one complete YubiHSM frame.
pub trait FrameTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError>;
    fn description(&self) -> String;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    Other,
    InvalidCommandFrame,
}

#[derive(Debug)]
pub struct TransportError {
    kind: TransportErrorKind,
    message: String,
}

impl TransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::Other,
            message: message.into(),
        }
    }

    fn invalid_command_frame(message: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::InvalidCommandFrame,
            message: message.into(),
        }
    }

    pub const fn kind(&self) -> TransportErrorKind {
        self.kind
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for TransportError {}

/// The direct adapter used for fast, deterministic local qualification.
pub struct InProcessTransport {
    device: Device,
}

impl InProcessTransport {
    pub fn new(device: Device) -> Self {
        Self { device }
    }

    pub fn factory_default() -> Self {
        Self::new(Device::factory_default(DeviceConfig::default()))
    }

    pub fn device(&self) -> &Device {
        &self.device
    }
}

impl FrameTransport for InProcessTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        Ok(self.device.handle_encoded(request))
    }

    fn description(&self) -> String {
        "in-process virtual-yubihsm-core".to_owned()
    }
}

/// Minimal HTTP adapter for the connector's binary command endpoint.
///
/// It intentionally supports plain `http://` only. TLS policy and client
/// authentication belong to the connector client being qualified separately;
/// protocol qualification normally runs over a loopback or private endpoint.
pub struct ConnectorHttpTransport {
    host: String,
    port: u16,
    path: String,
    serial: String,
    timeout: Duration,
}

impl ConnectorHttpTransport {
    pub fn new(base_url: &str, serial: impl Into<String>) -> Result<Self, TransportError> {
        let rest = base_url
            .strip_prefix("http://")
            .ok_or_else(|| TransportError::new("connector URL must start with http://"))?;
        let (authority, base_path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() {
            return Err(TransportError::new("connector URL has no host"));
        }
        let (host, port) = parse_authority(authority)?;
        let base_path = base_path.trim_matches('/');
        let prefix = if base_path.is_empty() {
            String::new()
        } else {
            format!("/{base_path}")
        };
        let serial = serial.into();
        if serial.is_empty() || !serial.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(TransportError::new(
                "serial must contain only ASCII letters and digits",
            ));
        }
        Ok(Self {
            host,
            port,
            path: format!("{prefix}/v1/devices/{serial}/commands"),
            serial,
            timeout: Duration::from_secs(120),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl FrameTransport for ConnectorHttpTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port)).map_err(|error| {
            TransportError::new(format!("connector connection failed: {error}"))
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| TransportError::new(format!("cannot set read timeout: {error}")))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| TransportError::new(format!("cannot set write timeout: {error}")))?;
        write!(
            stream,
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            self.host,
            self.port,
            request.len()
        )
        .and_then(|_| stream.write_all(request))
        .map_err(|error| TransportError::new(format!("connector request failed: {error}")))?;
        let mut encoded = Vec::new();
        stream
            .read_to_end(&mut encoded)
            .map_err(|error| TransportError::new(format!("connector response failed: {error}")))?;
        parse_http_response(&encoded)
    }

    fn description(&self) -> String {
        format!(
            "connector http://{}:{} serial {}",
            self.host, self.port, self.serial
        )
    }
}

fn parse_authority(authority: &str) -> Result<(String, u16), TransportError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| TransportError::new("invalid bracketed IPv6 connector host"))?;
        let port = match suffix {
            "" => 80,
            value if value.starts_with(':') => value[1..]
                .parse()
                .map_err(|_| TransportError::new("invalid connector port"))?,
            _ => return Err(TransportError::new("invalid connector authority")),
        };
        return Ok((host.to_owned(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((
            host.to_owned(),
            port.parse()
                .map_err(|_| TransportError::new("invalid connector port"))?,
        )),
        _ => Ok((authority.to_owned(), 80)),
    }
}

fn parse_http_response(encoded: &[u8]) -> Result<Vec<u8>, TransportError> {
    let boundary = encoded
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            TransportError::new(format!(
                "connector returned an invalid HTTP response ({} bytes)",
                encoded.len()
            ))
        })?;
    let head = std::str::from_utf8(&encoded[..boundary])
        .map_err(|_| TransportError::new("connector returned non-UTF-8 HTTP headers"))?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| TransportError::new("connector returned an invalid HTTP status"))?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<Vec<_>>();
    let body = &encoded[boundary + 4..];
    if status != 200 {
        let message = format!(
            "connector returned HTTP {status}: {}",
            String::from_utf8_lossy(body)
        );
        if status == 400
            && body
                .windows(b"\"code\":\"invalid_command_frame\"".len())
                .any(|window| window == b"\"code\":\"invalid_command_frame\"")
        {
            return Err(TransportError::invalid_command_frame(message));
        }
        return Err(TransportError::new(message));
    }
    if headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked"))
    {
        return decode_chunked(body);
    }
    if let Some((_, value)) = headers.iter().find(|(name, _)| name == "content-length") {
        let expected = value
            .parse::<usize>()
            .map_err(|_| TransportError::new("connector returned invalid Content-Length"))?;
        if expected != body.len() {
            return Err(TransportError::new(format!(
                "connector response body was {} bytes, expected {expected}",
                body.len()
            )));
        }
    }
    Ok(body.to_vec())
}

fn decode_chunked(mut encoded: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut output = Vec::new();
    loop {
        let line_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| TransportError::new("invalid chunked connector response"))?;
        let length_text = std::str::from_utf8(&encoded[..line_end])
            .map_err(|_| TransportError::new("invalid chunk length"))?;
        let length = usize::from_str_radix(length_text.split(';').next().unwrap(), 16)
            .map_err(|_| TransportError::new("invalid chunk length"))?;
        encoded = &encoded[line_end + 2..];
        if length == 0 {
            return Ok(output);
        }
        if encoded.len() < length + 2 || &encoded[length..length + 2] != b"\r\n" {
            return Err(TransportError::new("truncated chunked connector response"));
        }
        output.extend_from_slice(&encoded[..length]);
        encoded = &encoded[length + 2..];
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Read-only protocol and framing checks; safe for an unknown device.
    Smoke,
    /// Authenticated checks plus temporary objects which are deleted afterward.
    Managed,
    /// Managed checks plus project-supported protocol and algorithm additions.
    Extensions,
    /// Managed checks plus persistent audit-option/log checks; disposable targets only.
    Ephemeral,
}

#[derive(Clone)]
pub struct Credentials {
    pub authentication_key_id: u16,
    static_keys: Zeroizing<[u8; 32]>,
}

impl Credentials {
    pub fn from_password(authentication_key_id: u16, password: &[u8]) -> Self {
        Self {
            authentication_key_id,
            static_keys: yubico_password_kdf(password),
        }
    }

    pub fn from_static_keys(authentication_key_id: u16, static_keys: [u8; 32]) -> Self {
        Self {
            authentication_key_id,
            static_keys: Zeroizing::new(static_keys),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceIdentity {
    pub version: [u8; 3],
    pub serial: u32,
    pub log_capacity: u8,
    pub log_used: u8,
    pub algorithms: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub target: String,
    pub profile: Profile,
    pub identity: DeviceIdentity,
    pub passed: Vec<&'static str>,
}

#[derive(Debug)]
pub struct QualificationError {
    case: &'static str,
    message: String,
}

impl QualificationError {
    fn new(case: &'static str, message: impl Into<String>) -> Self {
        Self {
            case,
            message: message.into(),
        }
    }

    pub fn case(&self) -> &'static str {
        self.case
    }
}

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.case, self.message)
    }
}

impl Error for QualificationError {}

type CaseResult<T = ()> = Result<T, String>;

pub fn run(
    transport: &mut dyn FrameTransport,
    profile: Profile,
    credentials: Option<&Credentials>,
) -> Result<Report, QualificationError> {
    let target = transport.description();
    let mut passed = Vec::new();

    run_case(&mut passed, "malformed and unknown frames", || {
        match transport.exchange(&[CommandCode::Echo as u8, 0, 1]) {
            Ok(encoded) => {
                let response = Frame::parse(&encoded)
                    .map_err(|error| format!("invalid malformed-frame response: {error}"))?;
                expect_device_error(&response, DeviceError::WrongLength)?;
            }
            Err(error) if error.kind() == TransportErrorKind::InvalidCommandFrame => {}
            Err(error) => return Err(error.to_string()),
        }
        let response = exchange_frame(transport, Frame::new(0x02, Vec::new()).unwrap())?;
        expect_device_error(&response, DeviceError::InvalidCommand)
    })?;

    run_case(&mut passed, "plain echo", || {
        let payload = b"yubihsm qualification echo";
        let response = exchange_frame(
            transport,
            Frame::new(CommandCode::Echo as u8, payload.to_vec()).unwrap(),
        )?;
        let data = expect_response(&response, CommandCode::Echo)?;
        ensure(data == payload, "echo payload changed")
    })?;

    let identity = run_case_value(&mut passed, "device identity", || {
        let response = exchange_frame(
            transport,
            Frame::new(CommandCode::GetDeviceInfo as u8, Vec::new()).unwrap(),
        )?;
        let data = expect_response(&response, CommandCode::GetDeviceInfo)?;
        if data.len() < 9 {
            return Err(format!("device info is only {} bytes", data.len()));
        }
        Ok(DeviceIdentity {
            version: data[..3].try_into().unwrap(),
            serial: u32::from_be_bytes(data[3..7].try_into().unwrap()),
            log_capacity: data[7],
            log_used: data[8],
            algorithms: data[9..].to_vec(),
        })
    })?;

    run_case(&mut passed, "device public key", || {
        let response = exchange_frame(
            transport,
            Frame::new(CommandCode::GetDevicePublicKey as u8, Vec::new()).unwrap(),
        )?;
        let data = expect_response(&response, CommandCode::GetDevicePublicKey)?;
        ensure(
            data.len() == 65,
            format!("device public key is {} bytes", data.len()),
        )?;
        ensure(
            data[0] == Algorithm::EcP256YubicoAuthentication as u8,
            format!("unexpected device public-key algorithm 0x{:02x}", data[0]),
        )
    })?;

    run_case(&mut passed, "plain session boundary", || {
        let response = exchange_frame(
            transport,
            Frame::new(CommandCode::GetStorageInfo as u8, Vec::new()).unwrap(),
        )?;
        expect_device_error(&response, DeviceError::InvalidCommand)
    })?;

    if profile != Profile::Smoke {
        let credentials = credentials.ok_or_else(|| {
            QualificationError::new("credentials", "managed profiles require credentials")
        })?;
        run_managed(transport, credentials, &mut passed)?;
    }
    if profile == Profile::Extensions {
        let credentials = credentials.unwrap();
        run_extensions(transport, credentials, &mut passed)?;
    }
    if profile == Profile::Ephemeral {
        let credentials = credentials.unwrap();
        run_ephemeral_audit(transport, credentials, &mut passed)?;
    }

    Ok(Report {
        target,
        profile,
        identity,
        passed,
    })
}

fn run_managed(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
    passed: &mut Vec<&'static str>,
) -> Result<(), QualificationError> {
    run_case(passed, "symmetric authenticated session", || {
        let mut session = SymmetricSession::open(transport, credentials)?;
        let echo = Frame::new(CommandCode::Echo as u8, b"encrypted echo".to_vec()).unwrap();
        let response = session.command(transport, echo)?;
        ensure(
            expect_response(&response, CommandCode::Echo)? == b"encrypted echo",
            "encrypted echo payload changed",
        )?;
        let random = session.command(
            transport,
            Frame::new(CommandCode::GetPseudoRandom as u8, 32_u16.to_be_bytes()).unwrap(),
        )?;
        ensure(
            expect_response(&random, CommandCode::GetPseudoRandom)?.len() == 32,
            "random response has the wrong length",
        )?;
        session.close(transport)
    })?;

    run_case(passed, "opaque object lifecycle", || {
        let mut session = SymmetricSession::open(transport, credentials)?;
        let objects = list_objects(transport, &mut session)?;
        let id = unused_id(&objects, ObjectType::Opaque, 0x7e00)?;
        let payload = b"temporary qualification object";
        let capabilities = CapabilitySet::from_capabilities([Capability::GetOpaque]);
        let response = session.command(
            transport,
            put_opaque(id, 1, capabilities, "qualification", payload),
        )?;
        ensure(
            expect_response(&response, CommandCode::PutOpaque)? == id.to_be_bytes(),
            "Put Opaque returned a different object ID",
        )?;
        let response = session.command(
            transport,
            Frame::new(CommandCode::GetOpaque as u8, id.to_be_bytes()).unwrap(),
        )?;
        ensure(
            expect_response(&response, CommandCode::GetOpaque)? == payload,
            "Get Opaque returned different data",
        )?;
        let response = session.command(
            transport,
            Frame::new(
                CommandCode::GetObjectInfo as u8,
                object_key(id, ObjectType::Opaque),
            )
            .unwrap(),
        )?;
        ensure(
            expect_response(&response, CommandCode::GetObjectInfo)?.len() == 66,
            "object info is not 66 bytes",
        )?;
        let listed = list_objects(transport, &mut session)?;
        ensure(
            listed.contains(&(id, ObjectType::Opaque)),
            "new opaque object is missing from List Objects",
        )?;
        delete_object(transport, &mut session, id, ObjectType::Opaque)?;
        let response = session.command(
            transport,
            Frame::new(CommandCode::GetOpaque as u8, id.to_be_bytes()).unwrap(),
        )?;
        expect_device_error(&response, DeviceError::ObjectNotFound)?;
        session.close(transport)
    })?;

    run_case(
        passed,
        "authorization capabilities, delegation, and domains",
        || authorization_scenario(transport, credentials),
    )?;

    run_case(
        passed,
        "asymmetric authentication and session snapshot",
        || asymmetric_authentication_scenario(transport, credentials),
    )?;

    run_case(passed, "option inventory and validation", || {
        option_scenario(transport, credentials)
    })?;

    run_case(passed, "authenticated negative command matrix", || {
        negative_command_scenario(transport, credentials)
    })?;

    run_case(passed, "HMAC-SHA-256 known answer and verification", || {
        hmac_scenario(transport, credentials)
    })?;

    run_case(passed, "AES known answers and mode round trips", || {
        aes_scenario(transport, credentials)
    })?;

    run_case(passed, "authenticated data and object wrapping", || {
        wrapping_scenario(transport, credentials)
    })?;

    run_case(passed, "official EC curve signing matrix", || {
        ec_signing_scenario(transport, credentials)
    })?;

    run_case(passed, "RSA signing and decryption", || {
        rsa_scenario(transport, credentials)
    })?;

    run_case(passed, "RSA-AES wrapped objects and key material", || {
        rsa_wrapping_scenario(transport, credentials)
    })?;

    run_case(passed, "Ed25519 signing and P-256 ECDH", || {
        ed25519_and_ecdh_scenario(transport, credentials)
    })?;

    run_case(passed, "Yubico OTP AEAD known credential", || {
        otp_aead_scenario(transport, credentials)
    })?;

    run_case(passed, "attestation binds the generated public key", || {
        attestation_scenario(transport, credentials)
    })
}

fn otp_aead_scenario(transport: &mut dyn FrameTransport, credentials: &Credentials) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    let objects = list_objects(transport, &mut session)?;
    let id = unused_id(&objects, ObjectType::OtpAeadKey, 0x7b00)?;
    let capabilities = CapabilitySet::from_capabilities([
        Capability::CreateOtpAead,
        Capability::RandomizeOtpAead,
        Capability::DecryptOtp,
        Capability::RewrapFromOtpAeadKey,
        Capability::RewrapToOtpAeadKey,
    ]);
    let master_key = (0x80..=0x8f).collect::<Vec<_>>();
    let response = session.command(
        transport,
        put_otp_aead_key(id, capabilities, 0x1234_5678, &master_key),
    )?;
    expect_response(&response, CommandCode::PutOtpAeadKey)?;
    let credential_key = (0..=15).collect::<Vec<_>>();
    let mut create = id.to_be_bytes().to_vec();
    create.extend_from_slice(&credential_key);
    create.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    let response = session.command(
        transport,
        Frame::new(CommandCode::CreateOtpAead as u8, create).unwrap(),
    )?;
    let aead = expect_response(&response, CommandCode::CreateOtpAead)?.to_vec();
    ensure(aead.len() == 36, "Create OTP AEAD did not return 36 bytes")?;
    let otp = [
        0x2f, 0x5d, 0x71, 0xa4, 0x91, 0x5d, 0xec, 0x30, 0x4a, 0xa1, 0x3c, 0xcf, 0x97, 0xbb, 0x0d,
        0xbb,
    ];
    let mut decrypt = id.to_be_bytes().to_vec();
    decrypt.extend_from_slice(&aead);
    decrypt.extend_from_slice(&otp);
    let response = session.command(
        transport,
        Frame::new(CommandCode::DecryptOtp as u8, decrypt).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::DecryptOtp)? == [1, 0, 1, 1, 1, 0],
        "Decrypt OTP returned unexpected counters",
    )?;
    let response = session.command(
        transport,
        Frame::new(CommandCode::RandomizeOtpAead as u8, id.to_be_bytes()).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::RandomizeOtpAead)?.len() == 36,
        "Randomize OTP AEAD did not return 36 bytes",
    )?;
    delete_object(transport, &mut session, id, ObjectType::OtpAeadKey)?;
    session.close(transport)
}

fn attestation_scenario(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    let objects = list_objects(transport, &mut session)?;
    let id = unused_id(&objects, ObjectType::AsymmetricKey, 0x7b40)?;
    let response = session.command(
        transport,
        generate_asymmetric_key(
            id,
            CapabilitySet::from_capabilities([Capability::SignEcdsa]),
            Algorithm::EcP256,
            "qualification attest",
        ),
    )?;
    expect_response(&response, CommandCode::GenerateAsymmetricKey)?;
    let public = get_public_key(transport, &mut session, id, ObjectType::AsymmetricKey)?;
    let mut request = id.to_be_bytes().to_vec();
    request.extend_from_slice(&0_u16.to_be_bytes());
    let response = session.command(
        transport,
        Frame::new(CommandCode::SignAttestationCertificate as u8, request).unwrap(),
    )?;
    let certificate = Certificate::from_der(expect_response(
        &response,
        CommandCode::SignAttestationCertificate,
    )?)
    .map_err(|error| format!("attestation is not a DER certificate: {error}"))?;
    let certificate_public = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let mut expected_public = vec![0x04];
    expected_public.extend_from_slice(&public[1..]);
    ensure(
        certificate_public == expected_public,
        "attestation certificate contains a different public key",
    )?;
    delete_object(transport, &mut session, id, ObjectType::AsymmetricKey)?;
    session.close(transport)
}

fn ec_signing_scenario(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
) -> CaseResult {
    let curves = [
        (Algorithm::EcP224, EcCurve::P224, HashAlgorithm::Sha224, 28),
        (Algorithm::EcP256, EcCurve::P256, HashAlgorithm::Sha256, 32),
        (Algorithm::EcP384, EcCurve::P384, HashAlgorithm::Sha384, 48),
        (Algorithm::EcP521, EcCurve::P521, HashAlgorithm::Sha512, 66),
        (
            Algorithm::EcK256,
            EcCurve::Secp256k1,
            HashAlgorithm::Sha256,
            32,
        ),
        (
            Algorithm::EcBrainpoolP256,
            EcCurve::BrainpoolP256,
            HashAlgorithm::Sha256,
            32,
        ),
        (
            Algorithm::EcBrainpoolP384,
            EcCurve::BrainpoolP384,
            HashAlgorithm::Sha384,
            48,
        ),
        (
            Algorithm::EcBrainpoolP512,
            EcCurve::BrainpoolP512,
            HashAlgorithm::Sha512,
            64,
        ),
    ];
    let capabilities = CapabilitySet::from_capabilities([Capability::SignEcdsa]);
    let mut session = SymmetricSession::open(transport, credentials)?;
    let mut objects = list_objects(transport, &mut session)?;
    for (algorithm, curve, hash, coordinate_length) in curves {
        let id = unused_id(&objects, ObjectType::AsymmetricKey, 0x7c00)?;
        objects.insert((id, ObjectType::AsymmetricKey));
        let response = session.command(
            transport,
            generate_asymmetric_key(id, capabilities, algorithm, "qualification ec"),
        )?;
        expect_response(&response, CommandCode::GenerateAsymmetricKey)?;
        let public = get_public_key(transport, &mut session, id, ObjectType::AsymmetricKey)?;
        ensure(
            public.len() == 1 + coordinate_length * 2 && public[0] == algorithm as u8,
            format!("{algorithm:?} returned an invalid public key"),
        )?;
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&public[1..]);
        let verifier = SoftwarePublicKey::Ec {
            curve,
            uncompressed,
        };
        let digest = hash.digest(b"YubiHSM EC qualification message");
        let mut request = id.to_be_bytes().to_vec();
        request.extend_from_slice(&digest);
        let response = session.command(
            transport,
            Frame::new(CommandCode::SignEcdsa as u8, request).unwrap(),
        )?;
        let der = expect_response(&response, CommandCode::SignEcdsa)?;
        let signature = ecdsa_signature_from_der(der, coordinate_length)
            .map_err(|error| format!("{algorithm:?} returned invalid DER: {error:?}"))?;
        verifier
            .verify_prehash(curve.signature_scheme(), &digest, &signature)
            .map_err(|error| format!("{algorithm:?} signature did not verify: {error:?}"))?;
        delete_object(transport, &mut session, id, ObjectType::AsymmetricKey)?;
    }
    session.close(transport)
}

fn rsa_scenario(transport: &mut dyn FrameTransport, credentials: &Credentials) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    let objects = list_objects(transport, &mut session)?;
    let id = unused_id(&objects, ObjectType::AsymmetricKey, 0x7c40)?;
    let capabilities = CapabilitySet::from_capabilities([
        Capability::SignPkcs,
        Capability::SignPss,
        Capability::DecryptPkcs,
        Capability::DecryptOaep,
    ]);
    let response = session.command(
        transport,
        generate_asymmetric_key(id, capabilities, Algorithm::Rsa2048, "qualification rsa"),
    )?;
    expect_response(&response, CommandCode::GenerateAsymmetricKey)?;
    let public = get_public_key(transport, &mut session, id, ObjectType::AsymmetricKey)?;
    ensure(
        public.len() == 257 && public[0] == Algorithm::Rsa2048 as u8,
        "RSA-2048 returned an invalid public key",
    )?;
    let verifier = SoftwarePublicKey::Rsa {
        modulus: public[1..].to_vec(),
        exponent: vec![1, 0, 1],
    };
    let digest = HashAlgorithm::Sha256.digest(b"YubiHSM RSA qualification message");
    let mut request = id.to_be_bytes().to_vec();
    request.extend_from_slice(&digest);
    let response = session.command(
        transport,
        Frame::new(CommandCode::SignPkcs1 as u8, request).unwrap(),
    )?;
    let signature = expect_response(&response, CommandCode::SignPkcs1)?;
    verifier
        .verify_prehash(SignatureScheme::RsaPkcs1Sha256, &digest, signature)
        .map_err(|error| format!("RSA PKCS#1 signature did not verify: {error:?}"))?;

    let mut request = id.to_be_bytes().to_vec();
    request.push(Algorithm::Mgf1Sha256 as u8);
    request.extend_from_slice(&32_u16.to_be_bytes());
    request.extend_from_slice(&digest);
    let response = session.command(
        transport,
        Frame::new(CommandCode::SignPss as u8, request).unwrap(),
    )?;
    let signature = expect_response(&response, CommandCode::SignPss)?;
    verifier
        .verify_rsa_pss_prehash(SignatureScheme::RsaPssSha256, &digest, 32, signature)
        .map_err(|error| format!("RSA-PSS signature did not verify: {error:?}"))?;

    let plaintext = b"RSA qualification plaintext";
    let ciphertext = verifier
        .encrypt_rsa_pkcs1v15(plaintext)
        .map_err(|error| format!("local RSA encryption failed: {error:?}"))?;
    let mut request = id.to_be_bytes().to_vec();
    request.extend_from_slice(&ciphertext);
    let response = session.command(
        transport,
        Frame::new(CommandCode::DecryptPkcs1 as u8, request).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::DecryptPkcs1)? == plaintext,
        "RSA PKCS#1 decryption did not recover the plaintext",
    )?;

    let label_digest = HashAlgorithm::Sha256.digest(b"qualification OAEP label");
    let ciphertext = verifier
        .encrypt_rsa_oaep_digest(plaintext, &label_digest, HashAlgorithm::Sha384)
        .map_err(|error| format!("local RSA-OAEP encryption failed: {error:?}"))?;
    let mut request = id.to_be_bytes().to_vec();
    request.push(Algorithm::Mgf1Sha384 as u8);
    request.extend_from_slice(&ciphertext);
    request.extend_from_slice(&label_digest);
    let response = session.command(
        transport,
        Frame::new(CommandCode::DecryptOaep as u8, request).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::DecryptOaep)? == plaintext,
        "RSA-OAEP decryption did not recover the plaintext",
    )?;
    delete_object(transport, &mut session, id, ObjectType::AsymmetricKey)?;
    session.close(transport)
}

fn rsa_wrapping_scenario(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    let mut objects = list_objects(transport, &mut session)?;
    let private_wrap_id = unused_id(&objects, ObjectType::WrapKey, 0x7a00)?;
    objects.insert((private_wrap_id, ObjectType::WrapKey));
    let public_wrap_id = unused_id(&objects, ObjectType::PublicWrapKey, 0x7a10)?;
    objects.insert((public_wrap_id, ObjectType::PublicWrapKey));
    let opaque_id = unused_id(&objects, ObjectType::Opaque, 0x7a20)?;
    objects.insert((opaque_id, ObjectType::Opaque));
    let ec_id = unused_id(&objects, ObjectType::AsymmetricKey, 0x7a30)?;
    let opaque_capabilities =
        CapabilitySet::from_capabilities([Capability::GetOpaque, Capability::ExportableUnderWrap]);
    let ec_capabilities =
        CapabilitySet::from_capabilities([Capability::SignEcdsa, Capability::ExportableUnderWrap]);
    let delegated = CapabilitySet::from_capabilities([
        Capability::GetOpaque,
        Capability::SignEcdsa,
        Capability::ExportableUnderWrap,
    ]);

    let response = session.command(
        transport,
        generate_wrap_key(
            private_wrap_id,
            Algorithm::Rsa2048,
            CapabilitySet::from_capabilities([Capability::ImportWrapped]),
            delegated,
            "qualification private wrap",
        ),
    )?;
    expect_response(&response, CommandCode::GenerateWrapKey)?;
    let private_public = get_public_key(
        transport,
        &mut session,
        private_wrap_id,
        ObjectType::WrapKey,
    )?;
    ensure(
        private_public.len() == 257 && private_public[0] == Algorithm::Rsa2048 as u8,
        "RSA private wrap key returned an invalid public key",
    )?;
    let response = session.command(
        transport,
        put_public_wrap_key(
            public_wrap_id,
            Algorithm::Rsa2048,
            CapabilitySet::from_capabilities([Capability::ExportWrapped]),
            delegated,
            &private_public[1..],
        ),
    )?;
    expect_response(&response, CommandCode::PutPublicWrapKey)?;

    let response = session.command(
        transport,
        put_opaque(
            opaque_id,
            1,
            opaque_capabilities,
            "rsa-wrapped-object",
            b"RSA wrapped qualification object",
        ),
    )?;
    expect_response(&response, CommandCode::PutOpaque)?;
    let label_digest = HashAlgorithm::Sha256.digest(b"qualification RSA wrap label");
    let mut export = public_wrap_id.to_be_bytes().to_vec();
    export.push(ObjectType::Opaque as u8);
    export.extend_from_slice(&opaque_id.to_be_bytes());
    export.extend_from_slice(&[
        Algorithm::Aes256 as u8,
        Algorithm::RsaOaepSha256 as u8,
        Algorithm::Mgf1Sha384 as u8,
    ]);
    export.extend_from_slice(&label_digest);
    let response = session.command(
        transport,
        Frame::new(CommandCode::ExportRsaWrapped as u8, export).unwrap(),
    )?;
    let wrapped_object = expect_response(&response, CommandCode::ExportRsaWrapped)?.to_vec();
    ensure(
        wrapped_object.len() > 256,
        "RSA-wrapped object is too short",
    )?;
    delete_object(transport, &mut session, opaque_id, ObjectType::Opaque)?;
    let mut import = private_wrap_id.to_be_bytes().to_vec();
    import.extend_from_slice(&[Algorithm::RsaOaepSha256 as u8, Algorithm::Mgf1Sha384 as u8]);
    import.extend_from_slice(&wrapped_object);
    import.extend_from_slice(&label_digest);
    let response = session.command(
        transport,
        Frame::new(CommandCode::ImportRsaWrapped as u8, import).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::ImportRsaWrapped)?
            == [
                ObjectType::Opaque as u8,
                opaque_id.to_be_bytes()[0],
                opaque_id.to_be_bytes()[1],
            ],
        "Import RSA Wrapped returned a different object identity",
    )?;
    let response = session.command(
        transport,
        Frame::new(CommandCode::GetOpaque as u8, opaque_id.to_be_bytes()).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::GetOpaque)? == b"RSA wrapped qualification object",
        "RSA-wrapped object material changed",
    )?;

    let response = session.command(
        transport,
        generate_asymmetric_key(ec_id, ec_capabilities, Algorithm::EcP256, "wrapped ec key"),
    )?;
    expect_response(&response, CommandCode::GenerateAsymmetricKey)?;
    let ec_public = get_public_key(transport, &mut session, ec_id, ObjectType::AsymmetricKey)?;
    let mut get_wrapped = public_wrap_id.to_be_bytes().to_vec();
    get_wrapped.push(ObjectType::AsymmetricKey as u8);
    get_wrapped.extend_from_slice(&ec_id.to_be_bytes());
    get_wrapped.extend_from_slice(&[
        Algorithm::Aes256 as u8,
        Algorithm::RsaOaepSha256 as u8,
        Algorithm::Mgf1Sha384 as u8,
    ]);
    get_wrapped.extend_from_slice(&label_digest);
    let response = session.command(
        transport,
        Frame::new(CommandCode::GetRsaWrappedKey as u8, get_wrapped).unwrap(),
    )?;
    let wrapped_key = expect_response(&response, CommandCode::GetRsaWrappedKey)?.to_vec();
    delete_object(transport, &mut session, ec_id, ObjectType::AsymmetricKey)?;

    let mut put_wrapped = private_wrap_id.to_be_bytes().to_vec();
    put_wrapped.push(ObjectType::AsymmetricKey as u8);
    put_wrapped.extend_from_slice(&ec_id.to_be_bytes());
    put_wrapped.extend_from_slice(b"wrapped ec key");
    put_wrapped.resize(45, 0);
    put_wrapped.extend_from_slice(&1_u16.to_be_bytes());
    put_wrapped.extend_from_slice(&ec_capabilities.to_bytes());
    put_wrapped.extend_from_slice(&[
        Algorithm::EcP256 as u8,
        Algorithm::RsaOaepSha256 as u8,
        Algorithm::Mgf1Sha384 as u8,
    ]);
    put_wrapped.extend_from_slice(&wrapped_key);
    put_wrapped.extend_from_slice(&label_digest);
    let response = session.command(
        transport,
        Frame::new(CommandCode::PutRsaWrappedKey as u8, put_wrapped).unwrap(),
    )?;
    expect_response(&response, CommandCode::PutRsaWrappedKey)?;
    let digest = HashAlgorithm::Sha256.digest(b"restored RSA-wrapped EC key");
    let mut sign = ec_id.to_be_bytes().to_vec();
    sign.extend_from_slice(&digest);
    let response = session.command(
        transport,
        Frame::new(CommandCode::SignEcdsa as u8, sign).unwrap(),
    )?;
    let signature =
        ecdsa_signature_from_der(expect_response(&response, CommandCode::SignEcdsa)?, 32)
            .map_err(|error| format!("restored EC key returned invalid DER: {error:?}"))?;
    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(&ec_public[1..]);
    SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed,
    }
    .verify_prehash(SignatureScheme::EcdsaP256Sha256, &digest, &signature)
    .map_err(|error| format!("restored RSA-wrapped EC key changed: {error:?}"))?;

    for (id, object_type) in [
        (opaque_id, ObjectType::Opaque),
        (ec_id, ObjectType::AsymmetricKey),
        (public_wrap_id, ObjectType::PublicWrapKey),
        (private_wrap_id, ObjectType::WrapKey),
    ] {
        delete_object(transport, &mut session, id, object_type)?;
    }
    session.close(transport)
}

fn ed25519_and_ecdh_scenario(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    let mut objects = list_objects(transport, &mut session)?;
    let ed_id = unused_id(&objects, ObjectType::AsymmetricKey, 0x7c80)?;
    objects.insert((ed_id, ObjectType::AsymmetricKey));
    let response = session.command(
        transport,
        generate_asymmetric_key(
            ed_id,
            CapabilitySet::from_capabilities([Capability::SignEddsa]),
            Algorithm::Ed25519,
            "qualification ed25519",
        ),
    )?;
    expect_response(&response, CommandCode::GenerateAsymmetricKey)?;
    let public = get_public_key(transport, &mut session, ed_id, ObjectType::AsymmetricKey)?;
    ensure(
        public.len() == 33 && public[0] == Algorithm::Ed25519 as u8,
        "Ed25519 returned an invalid public key",
    )?;
    let verifier = SoftwarePublicKey::Edwards {
        curve: EdwardsCurve::Ed25519,
        public_key: public[1..].to_vec(),
    };
    let message = b"YubiHSM Ed25519 qualification message";
    let mut request = ed_id.to_be_bytes().to_vec();
    request.extend_from_slice(message);
    let response = session.command(
        transport,
        Frame::new(CommandCode::SignEddsa as u8, request).unwrap(),
    )?;
    verifier
        .verify_message(
            SignatureScheme::Ed25519,
            message,
            expect_response(&response, CommandCode::SignEddsa)?,
        )
        .map_err(|error| format!("Ed25519 signature did not verify: {error:?}"))?;

    let first_id = unused_id(&objects, ObjectType::AsymmetricKey, 0x7c90)?;
    objects.insert((first_id, ObjectType::AsymmetricKey));
    let second_id = unused_id(&objects, ObjectType::AsymmetricKey, 0x7c90)?;
    let agreement_capabilities = CapabilitySet::from_capabilities([Capability::DeriveEcdh]);
    for id in [first_id, second_id] {
        let response = session.command(
            transport,
            generate_asymmetric_key(
                id,
                agreement_capabilities,
                Algorithm::EcP256,
                "qualification ecdh",
            ),
        )?;
        expect_response(&response, CommandCode::GenerateAsymmetricKey)?;
    }
    let first_public =
        get_public_key(transport, &mut session, first_id, ObjectType::AsymmetricKey)?;
    let second_public = get_public_key(
        transport,
        &mut session,
        second_id,
        ObjectType::AsymmetricKey,
    )?;
    let first_secret = derive_ecdh(transport, &mut session, first_id, &second_public[1..])?;
    let second_secret = derive_ecdh(transport, &mut session, second_id, &first_public[1..])?;
    ensure(
        first_secret == second_secret && first_secret.len() == 32,
        "P-256 ECDH peers derived different secrets",
    )?;

    for id in [ed_id, first_id, second_id] {
        delete_object(transport, &mut session, id, ObjectType::AsymmetricKey)?;
    }
    session.close(transport)
}

fn run_extensions(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
    passed: &mut Vec<&'static str>,
) -> Result<(), QualificationError> {
    run_case(passed, "X25519 key agreement", || {
        x25519_scenario(transport, credentials)
    })?;
    run_case(passed, "prefixed ECDH KDF", || {
        prefixed_ecdh_kdf_scenario(transport, credentials)
    })
}

fn x25519_scenario(transport: &mut dyn FrameTransport, credentials: &Credentials) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    let objects = list_objects(transport, &mut session)?;
    let id = unused_id(&objects, ObjectType::AsymmetricKey, 0x7980)?;
    let response = session.command(
        transport,
        generate_asymmetric_key(
            id,
            CapabilitySet::from_capabilities([Capability::DeriveEcdh]),
            Algorithm::X25519,
            "qualification x25519",
        ),
    )?;
    expect_response(&response, CommandCode::GenerateAsymmetricKey)?;
    let public = get_public_key(transport, &mut session, id, ObjectType::AsymmetricKey)?;
    ensure(
        public.len() == 33 && public[0] == Algorithm::X25519 as u8,
        "X25519 returned an invalid public key",
    )?;
    let peer = SoftwareMontgomeryKey::from_serialized(MontgomeryCurve::X25519, &[0x33; 32])
        .map_err(|error| format!("invalid X25519 qualification peer: {error:?}"))?;
    let device_secret = derive_x25519(transport, &mut session, id, &peer.public_key())?;
    let peer_secret = peer
        .derive(&public[1..])
        .map_err(|error| format!("independent X25519 derivation failed: {error:?}"))?;
    ensure(
        device_secret == *peer_secret && device_secret.len() == 32,
        "X25519 device and independent peer derived different secrets",
    )?;
    delete_object(transport, &mut session, id, ObjectType::AsymmetricKey)?;
    session.close(transport)
}

fn prefixed_ecdh_kdf_scenario(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    let objects = list_objects(transport, &mut session)?;
    let id = unused_id(&objects, ObjectType::AsymmetricKey, 0x79a0)?;
    let response = session.command(
        transport,
        generate_asymmetric_key(
            id,
            CapabilitySet::from_capabilities([Capability::DeriveEcdhKdf]),
            Algorithm::EcP256,
            "qualification prefixed ecdh",
        ),
    )?;
    expect_response(&response, CommandCode::GenerateAsymmetricKey)?;
    let public = get_public_key(transport, &mut session, id, ObjectType::AsymmetricKey)?;
    ensure(
        public.len() == 65 && public[0] == Algorithm::EcP256 as u8,
        "prefixed ECDH key returned an invalid public key",
    )?;
    let peer = p256::SecretKey::from_slice(&[0x44; 32])
        .map_err(|error| format!("invalid prefixed-ECDH peer key: {error}"))?;
    let peer_public = peer.public_key().to_sec1_point(false);
    let device_public = p256::PublicKey::from_sec1_bytes(&[&[0x04], &public[1..]].concat())
        .map_err(|error| format!("invalid prefixed-ECDH device public key: {error}"))?;
    let raw_secret = diffie_hellman(peer.to_nonzero_scalar(), device_public.as_affine());
    let prefix = [0x41; 32];
    let shared_info = [0x3c, 0x88, 0x10];
    let mut kdf_input = Vec::with_capacity(prefix.len() + raw_secret.raw_secret_bytes().len());
    kdf_input.extend_from_slice(&prefix);
    kdf_input.extend_from_slice(raw_secret.raw_secret_bytes());
    let expected = x963_kdf_sha256(&kdf_input, &shared_info, 64)
        .map_err(|error| format!("independent prefixed-ECDH KDF failed: {error:?}"))?;
    let mut request = id.to_be_bytes().to_vec();
    request.push(3);
    request.extend_from_slice(&64_u16.to_be_bytes());
    for length in [
        peer_public.as_bytes().len(),
        prefix.len(),
        shared_info.len(),
    ] {
        request.extend_from_slice(
            &u16::try_from(length)
                .map_err(|_| "prefixed-ECDH input length overflow".to_owned())?
                .to_be_bytes(),
        );
    }
    request.extend_from_slice(peer_public.as_bytes());
    request.extend_from_slice(&prefix);
    request.extend_from_slice(&shared_info);
    let response = session.command(
        transport,
        Frame::new(CommandCode::DeriveEcdhKdf as u8, request).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::DeriveEcdhKdf)? == expected.as_slice(),
        "prefixed ECDH returned a different KDF result",
    )?;
    let response = session.command(
        transport,
        Frame::new(
            CommandCode::DeriveEcdh as u8,
            [id.to_be_bytes().as_slice(), peer_public.as_bytes()].concat(),
        )
        .unwrap(),
    )?;
    expect_device_error(&response, DeviceError::InsufficientPermissions)?;
    delete_object(transport, &mut session, id, ObjectType::AsymmetricKey)?;
    session.close(transport)
}

fn hmac_scenario(transport: &mut dyn FrameTransport, credentials: &Credentials) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    let objects = list_objects(transport, &mut session)?;
    let id = unused_id(&objects, ObjectType::HmacKey, 0x7d00)?;
    let capabilities =
        CapabilitySet::from_capabilities([Capability::SignHmac, Capability::VerifyHmac]);
    let key = [0x0b; 20];
    let message = b"Hi There";
    let response = session.command(
        transport,
        put_secret_key(
            CommandCode::PutHmacKey,
            id,
            capabilities,
            Algorithm::HmacSha256,
            &key,
            "qualification hmac",
        ),
    )?;
    expect_response(&response, CommandCode::PutHmacKey)?;

    let mut sign_data = id.to_be_bytes().to_vec();
    sign_data.extend_from_slice(message);
    let response = session.command(
        transport,
        Frame::new(CommandCode::SignHmac as u8, sign_data).unwrap(),
    )?;
    let signature = expect_response(&response, CommandCode::SignHmac)?.to_vec();
    let expected = hmac(HashAlgorithm::Sha256, &key, message)
        .map_err(|error| format!("local HMAC oracle failed: {error:?}"))?;
    ensure(signature == expected, "HMAC-SHA-256 known answer mismatch")?;

    let mut verify_data = id.to_be_bytes().to_vec();
    verify_data.extend_from_slice(&signature);
    verify_data.extend_from_slice(message);
    let response = session.command(
        transport,
        Frame::new(CommandCode::VerifyHmac as u8, verify_data.clone()).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::VerifyHmac)? == [1],
        "valid HMAC did not verify",
    )?;
    *verify_data.last_mut().unwrap() ^= 1;
    let response = session.command(
        transport,
        Frame::new(CommandCode::VerifyHmac as u8, verify_data).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::VerifyHmac)? == [0],
        "tampered HMAC input verified",
    )?;
    delete_object(transport, &mut session, id, ObjectType::HmacKey)?;
    session.close(transport)
}

fn aes_scenario(transport: &mut dyn FrameTransport, credentials: &Credentials) -> CaseResult {
    const PLAINTEXT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const IV: [u8; 16] = [
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x00,
    ];
    let vectors: [(Algorithm, &[u8], [u8; 16]); 3] = [
        (
            Algorithm::Aes128,
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a,
            ],
        ),
        (
            Algorithm::Aes192,
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            ],
            [
                0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
                0x71, 0x91,
            ],
        ),
        (
            Algorithm::Aes256,
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89,
            ],
        ),
    ];
    let capabilities = CapabilitySet::from_capabilities([
        Capability::EncryptEcb,
        Capability::DecryptEcb,
        Capability::EncryptCbc,
        Capability::DecryptCbc,
    ]);
    let mut session = SymmetricSession::open(transport, credentials)?;
    let mut objects = list_objects(transport, &mut session)?;
    for (algorithm, key, expected_ecb) in vectors {
        let id = unused_id(&objects, ObjectType::SymmetricKey, 0x7d20)?;
        objects.insert((id, ObjectType::SymmetricKey));
        let response = session.command(
            transport,
            put_secret_key(
                CommandCode::PutSymmetricKey,
                id,
                capabilities,
                algorithm,
                key,
                "qualification aes",
            ),
        )?;
        expect_response(&response, CommandCode::PutSymmetricKey)?;

        let mut ecb = id.to_be_bytes().to_vec();
        ecb.extend_from_slice(&PLAINTEXT);
        let response = session.command(
            transport,
            Frame::new(CommandCode::EncryptEcb as u8, ecb).unwrap(),
        )?;
        let ciphertext = expect_response(&response, CommandCode::EncryptEcb)?.to_vec();
        ensure(
            ciphertext == expected_ecb,
            format!("{algorithm:?} ECB known answer mismatch"),
        )?;
        let mut decrypt = id.to_be_bytes().to_vec();
        decrypt.extend_from_slice(&ciphertext);
        let response = session.command(
            transport,
            Frame::new(CommandCode::DecryptEcb as u8, decrypt).unwrap(),
        )?;
        ensure(
            expect_response(&response, CommandCode::DecryptEcb)? == PLAINTEXT,
            format!("{algorithm:?} ECB decrypt did not round trip"),
        )?;

        let mut cbc = id.to_be_bytes().to_vec();
        cbc.extend_from_slice(&IV);
        cbc.extend_from_slice(&PLAINTEXT);
        let response = session.command(
            transport,
            Frame::new(CommandCode::EncryptCbc as u8, cbc).unwrap(),
        )?;
        let ciphertext = expect_response(&response, CommandCode::EncryptCbc)?.to_vec();
        let mut decrypt = id.to_be_bytes().to_vec();
        decrypt.extend_from_slice(&IV);
        decrypt.extend_from_slice(&ciphertext);
        let response = session.command(
            transport,
            Frame::new(CommandCode::DecryptCbc as u8, decrypt).unwrap(),
        )?;
        ensure(
            expect_response(&response, CommandCode::DecryptCbc)? == PLAINTEXT,
            format!("{algorithm:?} CBC did not round trip"),
        )?;
        delete_object(transport, &mut session, id, ObjectType::SymmetricKey)?;
    }
    session.close(transport)
}

fn wrapping_scenario(transport: &mut dyn FrameTransport, credentials: &Credentials) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    let objects = list_objects(transport, &mut session)?;
    let wrap_id = unused_id(&objects, ObjectType::WrapKey, 0x7d60)?;
    let opaque_id = unused_id(&objects, ObjectType::Opaque, 0x7da0)?;
    let target_capabilities =
        CapabilitySet::from_capabilities([Capability::GetOpaque, Capability::ExportableUnderWrap]);
    let wrap_capabilities = CapabilitySet::from_capabilities([
        Capability::WrapData,
        Capability::UnwrapData,
        Capability::ExportWrapped,
        Capability::ImportWrapped,
    ]);
    let response = session.command(
        transport,
        put_wrap_key(
            wrap_id,
            Algorithm::Aes256CcmWrap,
            wrap_capabilities,
            target_capabilities,
            &[0x6d; 32],
        ),
    )?;
    expect_response(&response, CommandCode::PutWrapKey)?;

    let plaintext = b"qualification authenticated wrap data";
    let mut wrap_data = wrap_id.to_be_bytes().to_vec();
    wrap_data.extend_from_slice(plaintext);
    let response = session.command(
        transport,
        Frame::new(CommandCode::WrapData as u8, wrap_data).unwrap(),
    )?;
    let wrapped_data = expect_response(&response, CommandCode::WrapData)?.to_vec();
    ensure(
        wrapped_data.len() == 1 + 13 + plaintext.len() + 16,
        "Wrap Data response has the wrong envelope length",
    )?;
    let mut unwrap_data = wrap_id.to_be_bytes().to_vec();
    unwrap_data.extend_from_slice(&wrapped_data);
    let response = session.command(
        transport,
        Frame::new(CommandCode::UnwrapData as u8, unwrap_data.clone()).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::UnwrapData)? == plaintext,
        "Unwrap Data did not recover the plaintext",
    )?;
    *unwrap_data.last_mut().unwrap() ^= 1;
    let response = session.command(
        transport,
        Frame::new(CommandCode::UnwrapData as u8, unwrap_data).unwrap(),
    )?;
    expect_device_error(&response, DeviceError::InvalidData)?;

    let object_payload = b"qualification wrapped object";
    let response = session.command(
        transport,
        put_opaque(
            opaque_id,
            1,
            target_capabilities,
            "wrapped-object",
            object_payload,
        ),
    )?;
    expect_response(&response, CommandCode::PutOpaque)?;
    let mut export = wrap_id.to_be_bytes().to_vec();
    export.push(ObjectType::Opaque as u8);
    export.extend_from_slice(&opaque_id.to_be_bytes());
    let response = session.command(
        transport,
        Frame::new(CommandCode::ExportWrapped as u8, export).unwrap(),
    )?;
    let wrapped_object = expect_response(&response, CommandCode::ExportWrapped)?.to_vec();
    delete_object(transport, &mut session, opaque_id, ObjectType::Opaque)?;
    let mut import = wrap_id.to_be_bytes().to_vec();
    import.extend_from_slice(&wrapped_object);
    let response = session.command(
        transport,
        Frame::new(CommandCode::ImportWrapped as u8, import).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::ImportWrapped)?
            == [
                ObjectType::Opaque as u8,
                opaque_id.to_be_bytes()[0],
                opaque_id.to_be_bytes()[1],
            ],
        "Import Wrapped returned a different object identity",
    )?;
    let response = session.command(
        transport,
        Frame::new(CommandCode::GetOpaque as u8, opaque_id.to_be_bytes()).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::GetOpaque)? == object_payload,
        "wrapped object material changed across export/import",
    )?;
    delete_object(transport, &mut session, opaque_id, ObjectType::Opaque)?;
    delete_object(transport, &mut session, wrap_id, ObjectType::WrapKey)?;
    session.close(transport)
}

fn authorization_scenario(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
) -> CaseResult {
    let mut admin = SymmetricSession::open(transport, credentials)?;
    let objects = list_objects(transport, &mut admin)?;
    let authentication_id = unused_id(&objects, ObjectType::AuthenticationKey, 0x7e40)?;
    let opaque_id = unused_id(&objects, ObjectType::Opaque, 0x7e80)?;
    let restricted_keys = [0x42; 32];
    let capabilities =
        CapabilitySet::from_capabilities([Capability::GetOpaque, Capability::PutOpaque]);
    let delegated = CapabilitySet::from_capabilities([Capability::GetOpaque]);
    let response = admin.command(
        transport,
        put_authentication_key(
            authentication_id,
            1,
            capabilities,
            delegated,
            &restricted_keys,
        ),
    )?;
    expect_response(&response, CommandCode::PutAuthenticationKey)?;

    let restricted_credentials = Credentials::from_static_keys(authentication_id, restricted_keys);
    let outcome = (|| {
        let mut restricted = SymmetricSession::open(transport, &restricted_credentials)?;
        let response = restricted.command(
            transport,
            put_opaque(
                opaque_id,
                1,
                CapabilitySet::from_capabilities([Capability::GetOpaque]),
                "restricted",
                b"visible",
            ),
        )?;
        expect_response(&response, CommandCode::PutOpaque)?;
        let response = restricted.command(
            transport,
            Frame::new(CommandCode::GetOpaque as u8, opaque_id.to_be_bytes()).unwrap(),
        )?;
        ensure(
            expect_response(&response, CommandCode::GetOpaque)? == b"visible",
            "restricted session could not read its object",
        )?;
        let response = restricted.command(
            transport,
            put_opaque(
                opaque_id.wrapping_add(1),
                2,
                CapabilitySet::from_capabilities([Capability::GetOpaque]),
                "wrong-domain",
                b"hidden",
            ),
        )?;
        expect_device_error(&response, DeviceError::InsufficientPermissions)?;
        let response = restricted.command(
            transport,
            put_opaque(
                opaque_id.wrapping_add(2),
                1,
                CapabilitySet::from_capabilities([Capability::SignHmac]),
                "over-delegated",
                b"denied",
            ),
        )?;
        expect_device_error(&response, DeviceError::InsufficientPermissions)?;
        restricted.close(transport)
    })();

    let cleanup_opaque = delete_object(transport, &mut admin, opaque_id, ObjectType::Opaque);
    let cleanup_authentication = delete_object(
        transport,
        &mut admin,
        authentication_id,
        ObjectType::AuthenticationKey,
    );
    let close = admin.close(transport);
    outcome?;
    cleanup_opaque?;
    cleanup_authentication?;
    close
}

fn asymmetric_authentication_scenario(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
) -> CaseResult {
    let mut admin = SymmetricSession::open(transport, credentials)?;
    let objects = list_objects(transport, &mut admin)?;
    let authentication_id = unused_id(&objects, ObjectType::AuthenticationKey, 0x79c0)?;
    let host_static = p256::SecretKey::from_slice(&[0x11; 32])
        .map_err(|error| format!("invalid static qualification key: {error}"))?;
    let host_static_public = host_static.public_key().to_sec1_point(false);
    let response = admin.command(
        transport,
        put_asymmetric_authentication_key(
            authentication_id,
            4,
            CapabilitySet::from_capabilities([Capability::GetPseudoRandom]),
            CapabilitySet::from_capabilities([Capability::PutOpaque]),
            &host_static_public.as_bytes()[1..],
        ),
    )?;
    expect_response(&response, CommandCode::PutAuthenticationKey)?;

    let host_ephemeral = p256::SecretKey::from_slice(&[0x22; 32])
        .map_err(|error| format!("invalid ephemeral qualification key: {error}"))?;
    let host_ephemeral_public = host_ephemeral.public_key().to_sec1_point(false);
    let mut create = authentication_id.to_be_bytes().to_vec();
    create.extend_from_slice(host_ephemeral_public.as_bytes());
    let response = exchange_frame(
        transport,
        Frame::new(CommandCode::CreateSession as u8, create.clone()).unwrap(),
    )?;
    let create_response = expect_response(&response, CommandCode::CreateSession)?;
    ensure(
        create_response.len() == 82,
        format!(
            "asymmetric Create Session returned {} bytes",
            create_response.len()
        ),
    )?;
    let sid = create_response[0];
    let device_ephemeral = p256::PublicKey::from_sec1_bytes(&create_response[1..66])
        .map_err(|error| format!("invalid device ephemeral key: {error}"))?;
    let ephemeral_secret = diffie_hellman(
        host_ephemeral.to_nonzero_scalar(),
        device_ephemeral.as_affine(),
    );
    let device_public_response = exchange_frame(
        transport,
        Frame::new(CommandCode::GetDevicePublicKey as u8, Vec::new()).unwrap(),
    )?;
    let device_public = expect_response(&device_public_response, CommandCode::GetDevicePublicKey)?;
    let mut device_static_encoded = vec![0x04];
    device_static_encoded.extend_from_slice(&device_public[1..]);
    let device_static = p256::PublicKey::from_sec1_bytes(&device_static_encoded)
        .map_err(|error| format!("invalid device static key: {error}"))?;
    let static_secret = diffie_hellman(host_static.to_nonzero_scalar(), device_static.as_affine());
    let mut shared_secret = Vec::with_capacity(64);
    shared_secret.extend_from_slice(ephemeral_secret.raw_secret_bytes());
    shared_secret.extend_from_slice(static_secret.raw_secret_bytes());
    let session_keys = x963_kdf_sha256(&shared_secret, &[0x3c, 0x88, 0x10], 64)
        .map_err(|error| format!("asymmetric session KDF failed: {error:?}"))?;
    let mut receipt_input = create_response[1..66].to_vec();
    receipt_input.extend_from_slice(host_ephemeral_public.as_bytes());
    let receipt = aes_cmac(&session_keys[..16], &receipt_input)
        .map_err(|error| format!("asymmetric session receipt failed: {error:?}"))?;
    ensure(
        create_response[66..] == receipt,
        "asymmetric session receipt did not verify",
    )?;
    let mut counter = [0; AES_BLOCK_SIZE];
    counter[AES_BLOCK_SIZE - 1] = 1;
    let mut asymmetric = SymmetricSession {
        sid,
        s_enc: session_keys[16..32].try_into().unwrap(),
        s_mac: session_keys[32..48].try_into().unwrap(),
        s_rmac: session_keys[48..64].try_into().unwrap(),
        counter,
        command_mac: receipt,
    };
    let response = asymmetric.command(
        transport,
        Frame::new(CommandCode::GetPseudoRandom as u8, 16_u16.to_be_bytes()).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::GetPseudoRandom)?.len() == 16,
        "asymmetric session command returned the wrong length",
    )?;

    delete_object(
        transport,
        &mut admin,
        authentication_id,
        ObjectType::AuthenticationKey,
    )?;
    let response = asymmetric.command(
        transport,
        Frame::new(CommandCode::GetPseudoRandom as u8, 8_u16.to_be_bytes()).unwrap(),
    )?;
    ensure(
        expect_response(&response, CommandCode::GetPseudoRandom)?.len() == 8,
        "established asymmetric session lost its authorization snapshot",
    )?;
    let response = exchange_frame(
        transport,
        Frame::new(CommandCode::CreateSession as u8, create).unwrap(),
    )?;
    expect_device_error(&response, DeviceError::ObjectNotFound)?;
    asymmetric.close(transport)?;
    admin.close(transport)
}

fn option_scenario(transport: &mut dyn FrameTransport, credentials: &Credentials) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    for (option, expected_shape) in [
        (OPTION_FORCE_AUDIT, "scalar"),
        (OPTION_COMMAND_AUDIT, "pairs"),
        (0x04, "pairs"),
        (0x05, "scalar"),
    ] {
        let response = session.command(
            transport,
            Frame::new(CommandCode::GetOption as u8, vec![option]).unwrap(),
        )?;
        let value = expect_response(&response, CommandCode::GetOption)?;
        match expected_shape {
            "scalar" => ensure(
                value.len() == 1 && value[0] <= 2,
                format!("option 0x{option:02x} is not a valid scalar"),
            )?,
            "pairs" => ensure(
                !value.is_empty()
                    && value.len().is_multiple_of(2)
                    && value.as_chunks::<2>().0.iter().all(|pair| pair[1] <= 2),
                format!("option 0x{option:02x} is not a valid pair list"),
            )?,
            _ => unreachable!(),
        }
        if option == OPTION_COMMAND_AUDIT {
            ensure(
                value
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .find(|pair| pair[0] == CommandCode::SessionMessage as u8)
                    .is_none_or(|pair| pair[1] == 0),
                "Session Message was enabled in the command-audit option",
            )?;
        }
    }
    let response = session.command(
        transport,
        Frame::new(CommandCode::GetOption as u8, vec![0xff]).unwrap(),
    )?;
    expect_device_error(&response, DeviceError::InvalidData)?;
    session.close(transport)
}

fn negative_command_scenario(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
) -> CaseResult {
    let mut session = SymmetricSession::open(transport, credentials)?;
    for (command, data, expected) in [
        (
            CommandCode::GetPseudoRandom,
            vec![],
            DeviceError::WrongLength,
        ),
        (CommandCode::GetOption, vec![], DeviceError::WrongLength),
        (CommandCode::ListObjects, vec![1], DeviceError::WrongLength),
        (
            CommandCode::GetObjectInfo,
            vec![0, 1],
            DeviceError::WrongLength,
        ),
    ] {
        let response = session.command(transport, Frame::new(command as u8, data).unwrap())?;
        expect_device_error(&response, expected)?;
    }
    session.close(transport)
}

fn run_ephemeral_audit(
    transport: &mut dyn FrameTransport,
    credentials: &Credentials,
    passed: &mut Vec<&'static str>,
) -> Result<(), QualificationError> {
    run_case(
        passed,
        "audit logs inner commands but never Session Message",
        || {
            let mut admin = SymmetricSession::open(transport, credentials)?;
            let enable = vec![
                OPTION_COMMAND_AUDIT,
                0,
                4,
                CommandCode::CreateSession as u8,
                OPTION_ON,
                CommandCode::AuthenticateSession as u8,
                OPTION_ON,
            ];
            let response = admin.command(
                transport,
                Frame::new(CommandCode::SetOption as u8, enable).unwrap(),
            )?;
            expect_response(&response, CommandCode::SetOption)?;

            let mut second = SymmetricSession::open(transport, credentials)?;
            let response = second.command(
                transport,
                Frame::new(CommandCode::Echo as u8, b"not a meta log entry".to_vec()).unwrap(),
            )?;
            expect_response(&response, CommandCode::Echo)?;
            second.close(transport)?;

            let response = admin.command(
                transport,
                Frame::new(CommandCode::GetLogEntries as u8, Vec::new()).unwrap(),
            )?;
            let log = expect_response(&response, CommandCode::GetLogEntries)?;
            ensure(log.len() >= 5, "audit response is shorter than its header")?;
            ensure(
                log[4] == 2,
                format!("expected 2 audit entries, got {}", log[4]),
            )?;
            ensure(
                log.len() == 5 + usize::from(log[4]) * 32,
                "audit entry length mismatch",
            )?;
            ensure(
                log[7] == CommandCode::CreateSession as u8
                    && log[39] == CommandCode::AuthenticateSession as u8,
                "audit entries are not Create Session and Authenticate Session",
            )?;

            let invalid = vec![
                OPTION_COMMAND_AUDIT,
                0,
                2,
                CommandCode::SessionMessage as u8,
                OPTION_ON,
            ];
            let response = admin.command(
                transport,
                Frame::new(CommandCode::SetOption as u8, invalid).unwrap(),
            )?;
            expect_device_error(&response, DeviceError::InvalidData)?;
            admin.close(transport)
        },
    )?;

    run_case(
        passed,
        "force audit rejects commands when the log is full",
        || {
            let mut admin = SymmetricSession::open(transport, credentials)?;
            let response = admin.command(
                transport,
                Frame::new(
                    CommandCode::SetOption as u8,
                    vec![
                        OPTION_COMMAND_AUDIT,
                        0,
                        2,
                        CommandCode::GetPseudoRandom as u8,
                        OPTION_ON,
                    ],
                )
                .unwrap(),
            )?;
            expect_response(&response, CommandCode::SetOption)?;
            let response = admin.command(
                transport,
                Frame::new(
                    CommandCode::SetOption as u8,
                    vec![OPTION_FORCE_AUDIT, 0, 1, OPTION_ON],
                )
                .unwrap(),
            )?;
            expect_response(&response, CommandCode::SetOption)?;

            let response = admin.command(
                transport,
                Frame::new(CommandCode::GetDeviceInfo as u8, Vec::new()).unwrap(),
            )?;
            let info = expect_response(&response, CommandCode::GetDeviceInfo)?;
            ensure(
                info.len() >= 9,
                "device info is too short for audit capacity",
            )?;
            let capacity = usize::from(info[7]);
            let used = usize::from(info[8]);
            ensure(capacity > used, "audit log was already full")?;
            for _ in used..capacity {
                let response = admin.command(
                    transport,
                    Frame::new(CommandCode::GetPseudoRandom as u8, 1_u16.to_be_bytes()).unwrap(),
                )?;
                ensure(
                    expect_response(&response, CommandCode::GetPseudoRandom)?.len() == 1,
                    "audited random command returned the wrong length",
                )?;
            }
            let response = admin.command(
                transport,
                Frame::new(CommandCode::GetPseudoRandom as u8, 1_u16.to_be_bytes()).unwrap(),
            )?;
            expect_device_error(&response, DeviceError::LogFull)?;
            admin.close(transport)
        },
    )
}

fn run_case(
    passed: &mut Vec<&'static str>,
    name: &'static str,
    run: impl FnOnce() -> CaseResult,
) -> Result<(), QualificationError> {
    run().map_err(|message| QualificationError::new(name, message))?;
    passed.push(name);
    Ok(())
}

fn run_case_value<T>(
    passed: &mut Vec<&'static str>,
    name: &'static str,
    run: impl FnOnce() -> CaseResult<T>,
) -> Result<T, QualificationError> {
    let value = run().map_err(|message| QualificationError::new(name, message))?;
    passed.push(name);
    Ok(value)
}

fn ensure(condition: bool, message: impl Into<String>) -> CaseResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn exchange_raw(transport: &mut dyn FrameTransport, request: &[u8]) -> CaseResult<Frame> {
    let response = transport
        .exchange(request)
        .map_err(|error| error.to_string())?;
    Frame::parse(&response).map_err(|error| format!("invalid response frame: {error}"))
}

fn exchange_frame(transport: &mut dyn FrameTransport, request: Frame) -> CaseResult<Frame> {
    exchange_raw(transport, &request.encode())
}

fn expect_response(response: &Frame, command: CommandCode) -> CaseResult<&[u8]> {
    if response.command == ERROR_COMMAND {
        let error = response
            .data
            .first()
            .and_then(|value| DeviceError::from_byte(*value))
            .map_or_else(
                || format!("unknown device error payload {:02x?}", response.data),
                |error| error.to_string(),
            );
        return Err(format!("{} returned {error}", command_name(command)));
    }
    ensure(
        response.command == command as u8 | RESPONSE_BIT,
        format!(
            "{} returned response command 0x{:02x}",
            command_name(command),
            response.command
        ),
    )?;
    Ok(&response.data)
}

fn expect_device_error(response: &Frame, expected: DeviceError) -> CaseResult {
    ensure(
        response.command == ERROR_COMMAND && response.data == [expected as u8],
        format!("expected {expected}, got frame {:02x?}", response.encode()),
    )
}

fn command_name(command: CommandCode) -> String {
    format!("{command:?}")
}

struct SymmetricSession {
    sid: u8,
    s_enc: [u8; AES_BLOCK_SIZE],
    s_mac: [u8; AES_BLOCK_SIZE],
    s_rmac: [u8; AES_BLOCK_SIZE],
    counter: [u8; AES_BLOCK_SIZE],
    command_mac: [u8; AES_BLOCK_SIZE],
}

impl SymmetricSession {
    fn open(transport: &mut dyn FrameTransport, credentials: &Credentials) -> CaseResult<Self> {
        let host_challenge = [0x51, 0x75, 0x61, 0x6c, 0x69, 0x66, 0x79, 0x21];
        let mut create_data = credentials.authentication_key_id.to_be_bytes().to_vec();
        create_data.extend_from_slice(&host_challenge);
        let response = exchange_frame(
            transport,
            Frame::new(CommandCode::CreateSession as u8, create_data).unwrap(),
        )?;
        let create = expect_response(&response, CommandCode::CreateSession)?;
        ensure(
            create.len() == 17,
            format!("Create Session returned {} bytes", create.len()),
        )?;
        let sid = create[0];
        let mut context = [0; CHALLENGE_LENGTH * 2];
        context[..CHALLENGE_LENGTH].copy_from_slice(&host_challenge);
        context[CHALLENGE_LENGTH..].copy_from_slice(&create[1..9]);
        let s_enc = scp03_key(&credentials.static_keys[..16], 0x04, &context)
            .map_err(|error| format!("S-ENC derivation failed: {error:?}"))?;
        let s_mac = scp03_key(&credentials.static_keys[16..], 0x06, &context)
            .map_err(|error| format!("S-MAC derivation failed: {error:?}"))?;
        let s_rmac = scp03_key(&credentials.static_keys[16..], 0x07, &context)
            .map_err(|error| format!("S-RMAC derivation failed: {error:?}"))?;
        let card_cryptogram = scp03_cryptogram(&s_mac, 0x00, &context)
            .map_err(|error| format!("card cryptogram derivation failed: {error:?}"))?;
        ensure(
            create[9..] == card_cryptogram,
            "card cryptogram did not verify",
        )?;
        let host_cryptogram = scp03_cryptogram(&s_mac, 0x01, &context)
            .map_err(|error| format!("host cryptogram derivation failed: {error:?}"))?;
        let mut authenticate_payload = vec![sid];
        authenticate_payload.extend_from_slice(&host_cryptogram);
        let mut encoded_without_mac = vec![CommandCode::AuthenticateSession as u8, 0, 17];
        encoded_without_mac.extend_from_slice(&authenticate_payload);
        let mut mac_input = vec![0; AES_BLOCK_SIZE];
        mac_input.extend_from_slice(&encoded_without_mac);
        let command_mac = aes_cmac(&s_mac, &mac_input)
            .map_err(|error| format!("Authenticate Session MAC failed: {error:?}"))?;
        authenticate_payload.extend_from_slice(&command_mac[..MAC_LENGTH]);
        let response = exchange_frame(
            transport,
            Frame::new(CommandCode::AuthenticateSession as u8, authenticate_payload).unwrap(),
        )?;
        expect_response(&response, CommandCode::AuthenticateSession)?;
        let mut counter = [0; AES_BLOCK_SIZE];
        counter[AES_BLOCK_SIZE - 1] = 1;
        Ok(Self {
            sid,
            s_enc,
            s_mac,
            s_rmac,
            counter,
            command_mac,
        })
    }

    fn command(&mut self, transport: &mut dyn FrameTransport, inner: Frame) -> CaseResult<Frame> {
        let iv = encrypt_aes_block(&self.s_enc, &self.counter)
            .map_err(|error| format!("session IV generation failed: {error:?}"))?;
        let clear = pad_iso7816(&inner.encode());
        let ciphertext = encrypt_aes_cbc(&self.s_enc, &iv, &clear)
            .map_err(|error| format!("session encryption failed: {error:?}"))?;
        let mut data = vec![self.sid];
        data.extend_from_slice(&ciphertext);
        let total_length = data.len() + MAC_LENGTH;
        let mut encoded_without_mac = vec![
            CommandCode::SessionMessage as u8,
            (total_length >> 8) as u8,
            total_length as u8,
        ];
        encoded_without_mac.extend_from_slice(&data);
        let mut mac_input = self.command_mac.to_vec();
        mac_input.extend_from_slice(&encoded_without_mac);
        let command_mac = aes_cmac(&self.s_mac, &mac_input)
            .map_err(|error| format!("session command MAC failed: {error:?}"))?;
        data.extend_from_slice(&command_mac[..MAC_LENGTH]);
        let outer = exchange_frame(
            transport,
            Frame::new(CommandCode::SessionMessage as u8, data).unwrap(),
        )?;
        if outer.command == ERROR_COMMAND {
            return Ok(outer);
        }
        ensure(
            outer.command == CommandCode::SessionMessage as u8 | RESPONSE_BIT,
            format!(
                "unexpected Session Message response command 0x{:02x}",
                outer.command
            ),
        )?;
        ensure(
            outer.data.len() >= 1 + AES_BLOCK_SIZE + MAC_LENGTH,
            "Session Message response is too short",
        )?;
        let payload_length = outer.data.len() - MAC_LENGTH;
        let encoded = outer.encode();
        let mut rmac_input = command_mac.to_vec();
        rmac_input.extend_from_slice(&encoded[..3 + payload_length]);
        let expected_rmac = aes_cmac(&self.s_rmac, &rmac_input)
            .map_err(|error| format!("session response MAC failed: {error:?}"))?;
        ensure(
            outer.data[payload_length..] == expected_rmac[..MAC_LENGTH],
            "Session Message response MAC did not verify",
        )?;
        ensure(
            outer.data[0] == self.sid,
            "Session Message response changed SID",
        )?;
        let clear = decrypt_aes_cbc(&self.s_enc, &iv, &outer.data[1..payload_length])
            .map_err(|error| format!("session response decryption failed: {error:?}"))?;
        let clear = unpad_iso7816(clear)
            .map_err(|error| format!("session response padding failed: {error:?}"))?;
        let response = Frame::parse(&clear)
            .map_err(|error| format!("invalid inner response frame: {error}"))?;
        self.command_mac = command_mac;
        increment_counter(&mut self.counter);
        Ok(response)
    }

    fn close(&mut self, transport: &mut dyn FrameTransport) -> CaseResult {
        let response = self.command(
            transport,
            Frame::new(CommandCode::CloseSession as u8, Vec::new()).unwrap(),
        )?;
        expect_response(&response, CommandCode::CloseSession).map(|_| ())
    }
}

fn increment_counter(counter: &mut [u8; AES_BLOCK_SIZE]) {
    for byte in counter.iter_mut().rev() {
        let (value, overflow) = byte.overflowing_add(1);
        *byte = value;
        if !overflow {
            break;
        }
    }
}

fn list_objects(
    transport: &mut dyn FrameTransport,
    session: &mut SymmetricSession,
) -> CaseResult<BTreeSet<(u16, ObjectType)>> {
    let response = session.command(
        transport,
        Frame::new(CommandCode::ListObjects as u8, Vec::new()).unwrap(),
    )?;
    let data = expect_response(&response, CommandCode::ListObjects)?;
    ensure(
        data.len().is_multiple_of(4),
        "List Objects response is not a multiple of 4 bytes",
    )?;
    data.as_chunks::<4>()
        .0
        .iter()
        .map(|entry| {
            let id = u16::from_be_bytes(entry[..2].try_into().unwrap());
            let object_type = ObjectType::from_byte(entry[2])
                .ok_or_else(|| format!("List Objects returned unknown type 0x{:02x}", entry[2]))?;
            Ok((id, object_type))
        })
        .collect()
}

fn unused_id(
    objects: &BTreeSet<(u16, ObjectType)>,
    object_type: ObjectType,
    start: u16,
) -> CaseResult<u16> {
    (start..u16::MAX)
        .find(|id| !objects.contains(&(*id, object_type)))
        .ok_or_else(|| format!("no unused {object_type:?} object ID remains"))
}

fn put_opaque(
    id: u16,
    domains: u16,
    capabilities: CapabilitySet,
    label: &str,
    payload: &[u8],
) -> Frame {
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(label.as_bytes());
    data.resize(42, 0);
    data.extend_from_slice(&domains.to_be_bytes());
    data.extend_from_slice(&capabilities.to_bytes());
    data.push(Algorithm::OpaqueData as u8);
    data.extend_from_slice(payload);
    Frame::new(CommandCode::PutOpaque as u8, data).unwrap()
}

fn put_secret_key(
    command: CommandCode,
    id: u16,
    capabilities: CapabilitySet,
    algorithm: Algorithm,
    key: &[u8],
    label: &str,
) -> Frame {
    debug_assert!(matches!(
        command,
        CommandCode::PutHmacKey | CommandCode::PutSymmetricKey
    ));
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(label.as_bytes());
    data.resize(42, 0);
    data.extend_from_slice(&1_u16.to_be_bytes());
    data.extend_from_slice(&capabilities.to_bytes());
    data.push(algorithm as u8);
    data.extend_from_slice(key);
    Frame::new(command as u8, data).unwrap()
}

fn generate_asymmetric_key(
    id: u16,
    capabilities: CapabilitySet,
    algorithm: Algorithm,
    label: &str,
) -> Frame {
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(label.as_bytes());
    data.resize(42, 0);
    data.extend_from_slice(&1_u16.to_be_bytes());
    data.extend_from_slice(&capabilities.to_bytes());
    data.push(algorithm as u8);
    Frame::new(CommandCode::GenerateAsymmetricKey as u8, data).unwrap()
}

fn get_public_key(
    transport: &mut dyn FrameTransport,
    session: &mut SymmetricSession,
    id: u16,
    object_type: ObjectType,
) -> CaseResult<Vec<u8>> {
    let mut data = id.to_be_bytes().to_vec();
    if object_type != ObjectType::AsymmetricKey {
        data.push(object_type as u8);
    }
    let response = session.command(
        transport,
        Frame::new(CommandCode::GetPublicKey as u8, data).unwrap(),
    )?;
    expect_response(&response, CommandCode::GetPublicKey).map(<[u8]>::to_vec)
}

fn derive_ecdh(
    transport: &mut dyn FrameTransport,
    session: &mut SymmetricSession,
    id: u16,
    peer_public_without_marker: &[u8],
) -> CaseResult<Vec<u8>> {
    let mut data = id.to_be_bytes().to_vec();
    data.push(0x04);
    data.extend_from_slice(peer_public_without_marker);
    let response = session.command(
        transport,
        Frame::new(CommandCode::DeriveEcdh as u8, data).unwrap(),
    )?;
    expect_response(&response, CommandCode::DeriveEcdh).map(<[u8]>::to_vec)
}

fn derive_x25519(
    transport: &mut dyn FrameTransport,
    session: &mut SymmetricSession,
    id: u16,
    peer_public: &[u8],
) -> CaseResult<Vec<u8>> {
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(peer_public);
    let response = session.command(
        transport,
        Frame::new(CommandCode::DeriveEcdh as u8, data).unwrap(),
    )?;
    expect_response(&response, CommandCode::DeriveEcdh).map(<[u8]>::to_vec)
}

fn put_wrap_key(
    id: u16,
    algorithm: Algorithm,
    capabilities: CapabilitySet,
    delegated_capabilities: CapabilitySet,
    key: &[u8],
) -> Frame {
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(b"qualification wrap");
    data.resize(42, 0);
    data.extend_from_slice(&1_u16.to_be_bytes());
    data.extend_from_slice(&capabilities.to_bytes());
    data.push(algorithm as u8);
    data.extend_from_slice(&delegated_capabilities.to_bytes());
    data.extend_from_slice(key);
    Frame::new(CommandCode::PutWrapKey as u8, data).unwrap()
}

fn generate_wrap_key(
    id: u16,
    algorithm: Algorithm,
    capabilities: CapabilitySet,
    delegated_capabilities: CapabilitySet,
    label: &str,
) -> Frame {
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(label.as_bytes());
    data.resize(42, 0);
    data.extend_from_slice(&1_u16.to_be_bytes());
    data.extend_from_slice(&capabilities.to_bytes());
    data.push(algorithm as u8);
    data.extend_from_slice(&delegated_capabilities.to_bytes());
    Frame::new(CommandCode::GenerateWrapKey as u8, data).unwrap()
}

fn put_public_wrap_key(
    id: u16,
    algorithm: Algorithm,
    capabilities: CapabilitySet,
    delegated_capabilities: CapabilitySet,
    modulus: &[u8],
) -> Frame {
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(b"qualification public wrap");
    data.resize(42, 0);
    data.extend_from_slice(&1_u16.to_be_bytes());
    data.extend_from_slice(&capabilities.to_bytes());
    data.push(algorithm as u8);
    data.extend_from_slice(&delegated_capabilities.to_bytes());
    data.extend_from_slice(modulus);
    Frame::new(CommandCode::PutPublicWrapKey as u8, data).unwrap()
}

fn put_otp_aead_key(id: u16, capabilities: CapabilitySet, nonce_id: u32, key: &[u8]) -> Frame {
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(b"qualification otp");
    data.resize(42, 0);
    data.extend_from_slice(&1_u16.to_be_bytes());
    data.extend_from_slice(&capabilities.to_bytes());
    data.push(Algorithm::Aes128YubicoOtp as u8);
    data.extend_from_slice(&nonce_id.to_le_bytes());
    data.extend_from_slice(key);
    Frame::new(CommandCode::PutOtpAeadKey as u8, data).unwrap()
}

fn put_authentication_key(
    id: u16,
    domains: u16,
    capabilities: CapabilitySet,
    delegated_capabilities: CapabilitySet,
    static_keys: &[u8; 32],
) -> Frame {
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(b"qualification auth");
    data.resize(42, 0);
    data.extend_from_slice(&domains.to_be_bytes());
    data.extend_from_slice(&capabilities.to_bytes());
    data.push(AUTHENTICATION_ALGORITHM_AES128_YUBICO);
    data.extend_from_slice(&delegated_capabilities.to_bytes());
    data.extend_from_slice(static_keys);
    Frame::new(CommandCode::PutAuthenticationKey as u8, data).unwrap()
}

fn put_asymmetric_authentication_key(
    id: u16,
    domains: u16,
    capabilities: CapabilitySet,
    delegated_capabilities: CapabilitySet,
    public_key: &[u8],
) -> Frame {
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(b"qualification asymmetric auth");
    data.resize(42, 0);
    data.extend_from_slice(&domains.to_be_bytes());
    data.extend_from_slice(&capabilities.to_bytes());
    data.push(Algorithm::EcP256YubicoAuthentication as u8);
    data.extend_from_slice(&delegated_capabilities.to_bytes());
    data.extend_from_slice(public_key);
    Frame::new(CommandCode::PutAuthenticationKey as u8, data).unwrap()
}

fn object_key(id: u16, object_type: ObjectType) -> [u8; 3] {
    let [high, low] = id.to_be_bytes();
    [high, low, object_type as u8]
}

fn delete_object(
    transport: &mut dyn FrameTransport,
    session: &mut SymmetricSession,
    id: u16,
    object_type: ObjectType,
) -> CaseResult {
    let response = session.command(
        transport,
        Frame::new(CommandCode::DeleteObject as u8, object_key(id, object_type)).unwrap(),
    )?;
    expect_response(&response, CommandCode::DeleteObject).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_core_passes_the_complete_ephemeral_profile() {
        let mut transport = InProcessTransport::factory_default();
        let credentials = Credentials::from_password(1, b"password");
        let report = run(&mut transport, Profile::Ephemeral, Some(&credentials)).unwrap();
        assert_eq!(report.identity.serial, DeviceConfig::default().serial);
        assert_eq!(report.passed.len(), 22);
        assert_eq!(transport.device().active_session_count(), 0);
    }

    #[test]
    fn factory_core_passes_the_extension_profile() {
        let mut transport = InProcessTransport::factory_default();
        let credentials = Credentials::from_password(1, b"password");
        let report = run(&mut transport, Profile::Extensions, Some(&credentials)).unwrap();
        assert_eq!(report.passed.len(), 22);
        assert_eq!(transport.device().active_session_count(), 0);
    }

    #[test]
    fn smoke_profile_needs_no_credentials_and_does_not_open_a_session() {
        let mut transport = InProcessTransport::factory_default();
        let report = run(&mut transport, Profile::Smoke, None).unwrap();
        assert_eq!(report.passed.len(), 5);
        assert_eq!(transport.device().active_session_count(), 0);
    }

    #[test]
    fn parses_connector_urls_without_an_http_dependency() {
        let transport = ConnectorHttpTransport::new("http://127.0.0.1:12345", "12345678").unwrap();
        assert_eq!(transport.host, "127.0.0.1");
        assert_eq!(transport.port, 12345);
        assert_eq!(transport.path, "/v1/devices/12345678/commands");
    }
}
