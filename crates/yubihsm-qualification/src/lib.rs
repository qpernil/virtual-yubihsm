//! Transport-independent YubiHSM protocol qualification.
//!
//! Scenarios exchange complete, encoded YubiHSM frames through [`FrameTransport`].
//! The same expectations can therefore exercise the in-process virtual core, a
//! connector-hosted embedded core, a USB-gadget instance, or physical hardware.

use software_key_core::{
    secure_channel::{
        pad_iso7816, scp03_cryptogram, scp03_key, unpad_iso7816, yubico_password_kdf,
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
use zeroize::Zeroizing;

const RESPONSE_BIT: u8 = 0x80;
const ERROR_COMMAND: u8 = 0x7f;
const MAC_LENGTH: usize = 8;
const CHALLENGE_LENGTH: usize = 8;
const AUTHENTICATION_ALGORITHM_AES128_YUBICO: u8 = Algorithm::Aes128YubicoAuthentication as u8;
const OPTION_COMMAND_AUDIT: u8 = 0x03;
const OPTION_ON: u8 = 1;

/// A transport capable of exchanging one complete YubiHSM frame.
pub trait FrameTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError>;
    fn description(&self) -> String;
}

#[derive(Debug)]
pub struct TransportError(String);

impl TransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
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
        return Err(TransportError::new(format!(
            "connector returned HTTP {status}: {}",
            String::from_utf8_lossy(body)
        )));
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
        let response = exchange_raw(transport, &[CommandCode::Echo as u8, 0, 1])?;
        expect_device_error(&response, DeviceError::WrongLength)?;
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
        expect_device_error(&response, DeviceError::InvalidSession)
    })?;

    if profile != Profile::Smoke {
        let credentials = credentials.ok_or_else(|| {
            QualificationError::new("credentials", "managed profiles require credentials")
        })?;
        run_managed(transport, credentials, &mut passed)?;
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
    )
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
        assert_eq!(report.passed.len(), 9);
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
