use crate::object::StoredObjectRecord;
use crate::{
    Algorithm, AuthenticationKeyMaterial, Capability, CapabilitySet, CommandCode, DeviceError,
    FirmwareProfile, Frame, ObjectInfo, ObjectKey, ObjectMaterial, ObjectRecord, ObjectType,
    Result, SessionAuthorization, SessionObjectCommand,
    request::*,
    session::{
        AUTHENTICATION_ALGORITHM_AES128_YUBICO, AUTHENTICATION_ALGORITHM_EC_P256, CHALLENGE_LENGTH,
        P256_PUBLIC_KEY_LENGTH, SecureSession, SessionEntry, random_secret_key,
        secure_response_data_fits, secure_response_fits,
    },
    session_object::{
        FLAG_DERIVE, FLAG_READABLE, FLAG_VERIFY, SessionObject, SessionObjectKind, SessionObjects,
    },
    wire::{Reader as WireReader, decode as decode_request},
};
use ciborium::Value as CborValue;
use const_oid::ObjectIdentifier;
use der::{
    Decode, Encode, Sequence,
    asn1::{BitString, OctetString},
};
use serde::{Deserialize, Serialize};
use software_key_core::{
    certificate_signing::{CertificateSignature, CertificateSigner, subject_public_key_info},
    counter_kdf::cmac_counter_kdf,
    digest::{HashAlgorithm, x963_kdf},
    rsa_signing::RsaHashAlgorithm,
    secure_channel::yubico_password_kdf,
    software_key_agreement::{MontgomeryCurve, SoftwareMontgomeryKey, derive_with_signing_key},
    software_signing::{
        EcCurve, EdwardsCurve, KeyKind, SignatureScheme, SoftwarePublicKey, SoftwareSigningKey,
    },
    software_symmetric::{
        AES_BLOCK_SIZE, AES_CCM_NONCE_SIZE, AES_CCM_TAG_SIZE, aes_cmac, decrypt_aes_cbc,
        decrypt_aes_ccm, decrypt_aes_ecb, decrypt_yubico_otp_aead, encrypt_aes_cbc,
        encrypt_aes_ccm, encrypt_aes_ecb, encrypt_yubico_otp_aead, unwrap_aes_kwp, wrap_aes_kwp,
    },
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::{collections::BTreeMap, io::Cursor};
use std::{
    str::FromStr,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use x509_cert::{
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    certificate::TbsCertificate,
    ext::{
        Extension, ToExtension,
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
    },
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};
use zeroize::Zeroizing;

const MAX_OBJECTS: usize = 256;
const MAX_SESSIONS: u8 = 16;
const SESSION_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_AUTHENTICATION_ALGORITHM: u8 = AUTHENTICATION_ALGORITHM_AES128_YUBICO;
const OPAQUE_DATA_ALGORITHM: u8 = 30;
const PERSISTENT_STATE_SCHEMA: &str = "virtual-yubihsm-state";
const PERSISTENT_STATE_VERSION: u16 = 3;
const WRAPPED_OBJECT_SCHEMA: &str = "virtual-yubihsm-object";
const WRAPPED_OBJECT_VERSION: u8 = 1;
const WRAPPED_MATERIAL_SECRET: u8 = 0;
const WRAPPED_MATERIAL_PKCS8: u8 = 1;
const WRAPPED_MATERIAL_OPAQUE: u8 = 2;
const WRAPPED_MATERIAL_PUBLIC: u8 = 3;
const WRAPPED_MATERIAL_AUTHENTICATION_SYMMETRIC: u8 = 4;
const WRAPPED_MATERIAL_AUTHENTICATION_ASYMMETRIC: u8 = 5;
const WRAPPED_MATERIAL_OTP_AEAD: u8 = 6;
const OPTION_FORCE_AUDIT: u8 = 0x01;
const OPTION_COMMAND_AUDIT: u8 = 0x03;
const OPTION_ALGORITHM_TOGGLE: u8 = 0x04;
const OPTION_FIPS_MODE: u8 = 0x05;
const OPTION_OFF: u8 = 0;
const OPTION_ON: u8 = 1;
const OPTION_FIX: u8 = 2;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceConfig {
    pub version: [u8; 3],
    pub serial: u32,
    pub log_capacity: u8,
    pub algorithms: Vec<u8>,
    pub part_number: [u8; 13],
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct DeviceOptions {
    force_audit: u8,
    command_audit: BTreeMap<u8, u8>,
    algorithm_toggle: BTreeMap<u8, u8>,
    fips_mode: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AuditEntry {
    number: u16,
    command: u8,
    length: u16,
    session_key: u16,
    target_key: u16,
    second_key: u16,
    result: u8,
    systick: u32,
    digest: [u8; 16],
}

impl AuditEntry {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.number.to_be_bytes());
        output.push(self.command);
        output.extend_from_slice(&self.length.to_be_bytes());
        output.extend_from_slice(&self.session_key.to_be_bytes());
        output.extend_from_slice(&self.target_key.to_be_bytes());
        output.extend_from_slice(&self.second_key.to_be_bytes());
        output.push(self.result);
        output.extend_from_slice(&self.systick.to_be_bytes());
        output.extend_from_slice(&self.digest);
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct AuditState {
    entries: Vec<AuditEntry>,
    next_number: u16,
    systick: u32,
    previous_digest: [u8; 16],
    unlogged_boot: u16,
    unlogged_authentication: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistentState {
    schema: String,
    version: u16,
    config: DeviceConfig,
    objects: Vec<StoredObjectRecord>,
    device_static_private: [u8; 32],
    state_epoch: u64,
    sequence_history: SequenceHistory,
    options: DeviceOptions,
    audit: AuditState,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct SequenceHistory {
    entries: BTreeMap<u16, u64>,
}

impl SequenceHistory {
    fn validate(&self) -> bool {
        self.entries.keys().all(|id| *id != 0 && *id != u16::MAX)
    }

    fn generation(&self, id: u16) -> Option<u64> {
        self.entries.get(&id).copied()
    }

    fn record(&mut self, id: u16, generation: u64) {
        self.entries.insert(id, generation);
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

struct AttestationProfile {
    subject: Name,
    issuer: Name,
    key_agreement: bool,
    key_encipherment: bool,
    template_extensions: Vec<Extension>,
    metadata_extensions: Vec<Extension>,
}

impl BuilderProfile for AttestationProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _subject_key: spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_key: spki::SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions = self.template_extensions.clone();
        if extensions.is_empty() {
            extensions.push(
                BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                }
                .to_extension(tbs.subject(), &extensions)?,
            );
            let mut usages = KeyUsages::DigitalSignature.into();
            if self.key_agreement {
                usages |= KeyUsages::KeyAgreement;
            }
            if self.key_encipherment {
                usages |= KeyUsages::KeyEncipherment;
            }
            extensions.push(KeyUsage(usages).to_extension(tbs.subject(), &extensions)?);
        }
        extensions.extend(self.metadata_extensions.clone());
        Ok(extensions)
    }
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            version: [2, 5, 0],
            serial: 12_345_678,
            log_capacity: 62,
            algorithms: Algorithm::OFFICIAL
                .into_iter()
                .chain([
                    Algorithm::X25519,
                    Algorithm::X448,
                    Algorithm::Ed448,
                    Algorithm::MlDsa44,
                    Algorithm::MlDsa65,
                    Algorithm::MlDsa87,
                    Algorithm::MlKem512,
                    Algorithm::MlKem768,
                    Algorithm::MlKem1024,
                ])
                .filter(|algorithm| algorithm.supported_by_firmware())
                .map(|algorithm| algorithm as u8)
                .collect(),
            part_number: *b"78CLUFX5000P\0",
        }
    }
}

#[derive(Debug)]
pub struct Device {
    config: DeviceConfig,
    objects: BTreeMap<ObjectKey, ObjectRecord>,
    sessions: BTreeMap<u8, SessionEntry>,
    device_static_private: SoftwareSigningKey,
    state_epoch: u64,
    sequence_history: SequenceHistory,
    options: DeviceOptions,
    audit: AuditState,
    persistent_change: bool,
}

impl Device {
    pub fn factory_default(config: DeviceConfig) -> Self {
        Self::factory_default_with_device_static_private(
            config,
            random_device_static_private().expect("operating-system random source unavailable"),
        )
        .expect("generated P-256 device key is invalid")
    }

    /// Construct a device with an explicitly supplied P-256 static key.
    ///
    /// This is primarily useful for persisted device identities and
    /// deterministic compatibility fixtures. The key is copied into
    /// zeroizing device storage and is never exposed again.
    pub fn factory_default_with_device_static_private(
        config: DeviceConfig,
        device_static_private: [u8; 32],
    ) -> Result<Self> {
        let device_static_private = SoftwareSigningKey::from_serialized_for_kind(
            KeyKind::Ec(EcCurve::P256),
            &device_static_private,
        )
        .map_err(|_| DeviceError::InvalidData)?;
        let mut device = Self {
            config,
            objects: BTreeMap::new(),
            sessions: BTreeMap::new(),
            device_static_private,
            state_epoch: 0,
            sequence_history: SequenceHistory::default(),
            options: DeviceOptions::default(),
            audit: AuditState {
                next_number: 1,
                ..AuditState::default()
            },
            persistent_change: false,
        };
        device.install_factory_authentication_key();
        Ok(device)
    }

    /// Process one complete YubiHSM connector message.
    pub fn handle_encoded(&mut self, encoded: &[u8]) -> Vec<u8> {
        let response = match Frame::parse(encoded) {
            Ok(request) => self.handle_frame(request),
            Err(error) => Frame::error(error),
        };
        response.encode()
    }

    /// Process a message while allowing a transport or compatibility fixture
    /// to handle selected decrypted commands. Returning `None` delegates the
    /// command to the built-in device implementation.
    ///
    /// The core always enforces the command's session capability before the
    /// handler runs. A handler which overrides an object command remains
    /// responsible for the selected object's capabilities and domains.
    pub fn handle_encoded_with<F>(&mut self, encoded: &[u8], mut handler: F) -> Vec<u8>
    where
        F: FnMut(SessionAuthorization, &Frame) -> Option<Frame>,
    {
        let response = match Frame::parse(encoded) {
            Ok(request) => self.handle_frame_with(request, &mut handler),
            Err(error) => Frame::error(error),
        };
        response.encode()
    }

    /// Process a message with the built-in implementation and observe the
    /// decrypted command and response. The observer cannot replace device
    /// behavior, so authorization, auditing, and state changes remain owned by
    /// the core. This is intended for transport-adjacent effects such as a
    /// physical activity display.
    pub fn handle_encoded_observing<O>(&mut self, encoded: &[u8], mut observer: O) -> Vec<u8>
    where
        O: FnMut(SessionAuthorization, &Frame, &Frame),
    {
        let response = match Frame::parse(encoded) {
            Ok(request) => self.handle_frame_with_hooks(request, &mut |_, _| None, &mut observer),
            Err(error) => Frame::error(error),
        };
        response.encode()
    }

    /// Process one complete outer protocol frame.
    pub fn handle_frame(&mut self, request: Frame) -> Frame {
        self.handle_frame_with(request, &mut |_, _| None)
    }

    fn handle_frame_with<F>(&mut self, request: Frame, handler: &mut F) -> Frame
    where
        F: FnMut(SessionAuthorization, &Frame) -> Option<Frame>,
    {
        self.handle_frame_with_hooks(request, handler, &mut |_, _, _| {})
    }

    fn handle_frame_with_hooks<F, O>(
        &mut self,
        request: Frame,
        handler: &mut F,
        observer: &mut O,
    ) -> Frame
    where
        F: FnMut(SessionAuthorization, &Frame) -> Option<Frame>,
        O: FnMut(SessionAuthorization, &Frame, &Frame),
    {
        self.expire_inactive_sessions(Instant::now());
        let result = match CommandCode::from_byte(request.command) {
            Some(
                CommandCode::Echo | CommandCode::GetDeviceInfo | CommandCode::GetDevicePublicKey,
            ) => {
                return self.execute_plain(&request);
            }
            Some(CommandCode::CreateSession) => self.create_session(&request),
            Some(CommandCode::AuthenticateSession) => self.authenticate_session(&request),
            Some(CommandCode::SessionMessage) => {
                self.session_message_with(&request, handler, observer)
            }
            Some(_) => Err(DeviceError::InvalidCommand),
            None => Err(DeviceError::InvalidCommand),
        };
        result.unwrap_or_else(Frame::error)
    }

    pub fn session_authorization(
        &self,
        authentication_key_id: u16,
    ) -> Result<SessionAuthorization> {
        let record = self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::AuthenticationKey,
                id: authentication_key_id,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        if !matches!(record.material, ObjectMaterial::Authentication(_)) {
            return Err(DeviceError::InvalidData);
        }
        Ok(SessionAuthorization {
            authentication_key_id,
            capabilities: record.info.capabilities,
            delegated_capabilities: record.info.delegated_capabilities,
            domains: record.info.domains,
        })
    }

    pub fn authentication_key_material(
        &self,
        authentication_key_id: u16,
    ) -> Result<&AuthenticationKeyMaterial> {
        match &self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::AuthenticationKey,
                id: authentication_key_id,
            })
            .ok_or(DeviceError::ObjectNotFound)?
            .material
        {
            ObjectMaterial::Authentication(material) => Ok(material),
            _ => Err(DeviceError::InvalidData),
        }
    }

    /// Handle a command that is valid outside a secure session.
    pub fn execute_plain(&self, request: &Frame) -> Frame {
        let result = self
            .execute_plain_or_authenticated(request)
            .unwrap_or(Err(DeviceError::InvalidCommand));
        match result {
            Ok(data) => Frame::response(request.command, data),
            Err(error) => Frame::error(error),
        }
    }

    /// Commands accepted both directly and inside an authenticated session.
    fn execute_plain_or_authenticated(&self, request: &Frame) -> Option<Result<Vec<u8>>> {
        Some(match CommandCode::from_byte(request.command)? {
            CommandCode::Echo => {
                decode_request::<EchoRequest>(&request.data).map(|request| request.data.to_vec())
            }
            CommandCode::GetDeviceInfo => self.get_device_info(&request.data),
            CommandCode::GetDevicePublicKey => self.get_device_public_key(&request.data),
            _ => return None,
        })
    }

    fn create_session(&mut self, request: &Frame) -> Result<Frame> {
        let decoded = decode_request::<CreateSessionRequest>(&request.data)?;
        let authentication_key_id = decoded.authentication_key_id;
        let authorization = self.session_authorization(authentication_key_id)?;
        let result = (|| {
            let material = self
                .authentication_key_material(authentication_key_id)?
                .clone();
            let sid = (0..MAX_SESSIONS)
                .find(|sid| !self.sessions.contains_key(sid))
                .ok_or(DeviceError::SessionsFull)?;

            match &material {
                AuthenticationKeyMaterial::Symmetric(static_keys) => {
                    if decoded.host_challenge_or_public_key.len() != CHALLENGE_LENGTH {
                        return Err(DeviceError::WrongLength);
                    }
                    let mut card_challenge = [0; CHALLENGE_LENGTH];
                    getrandom::fill(&mut card_challenge).map_err(|_| DeviceError::StorageFailed)?;
                    let (secure, card_cryptogram, expected_host_cryptogram) =
                        SecureSession::begin_symmetric(
                            sid,
                            static_keys,
                            decoded.host_challenge_or_public_key,
                            card_challenge,
                        )?;
                    self.sessions.insert(
                        sid,
                        SessionEntry {
                            authorization,
                            secure,
                            expected_host_cryptogram: Some(expected_host_cryptogram),
                            authenticated: false,
                            last_activity: Instant::now(),
                            objects: SessionObjects::default(),
                        },
                    );
                    let mut response = Vec::with_capacity(1 + CHALLENGE_LENGTH + 8);
                    response.push(sid);
                    response.extend_from_slice(&card_challenge);
                    response.extend_from_slice(&card_cryptogram);
                    Ok(Frame::response(CommandCode::CreateSession as u8, response))
                }
                AuthenticationKeyMaterial::Asymmetric(host_static_public) => {
                    if decoded.host_challenge_or_public_key.len() != P256_PUBLIC_KEY_LENGTH {
                        return Err(DeviceError::WrongLength);
                    }
                    let (secure, device_ephemeral_public, receipt) =
                        SecureSession::begin_asymmetric(
                            sid,
                            &self.device_static_private,
                            host_static_public,
                            decoded.host_challenge_or_public_key,
                        )?;
                    self.sessions.insert(
                        sid,
                        SessionEntry {
                            authorization,
                            secure,
                            expected_host_cryptogram: None,
                            authenticated: true,
                            last_activity: Instant::now(),
                            objects: SessionObjects::default(),
                        },
                    );
                    let mut response = Vec::with_capacity(1 + P256_PUBLIC_KEY_LENGTH + 16);
                    response.push(sid);
                    response.extend_from_slice(&device_ephemeral_public);
                    response.extend_from_slice(&receipt);
                    self.record_unlogged_authentication_if_full();
                    Ok(Frame::response(CommandCode::CreateSession as u8, response))
                }
            }
        })();
        if self.should_audit(CommandCode::CreateSession) {
            let result_code = result
                .as_ref()
                .err()
                .copied()
                .map_or(0, |error| error as u8);
            self.append_audit_entry(
                authorization,
                CommandCode::CreateSession,
                request,
                result_code,
            );
        }
        result
    }

    fn authenticate_session(&mut self, request: &Frame) -> Result<Frame> {
        let sid = decode_request::<AuthenticateSessionRequest>(&request.data)?
            .0
            .session_id;
        let mut entry = self
            .sessions
            .remove(&sid)
            .ok_or(DeviceError::InvalidSession)?;
        let authorization = entry.authorization;
        let result = (|| {
            if entry.authenticated {
                return Err(DeviceError::InvalidSession);
            }
            let expected = entry
                .expected_host_cryptogram
                .take()
                .ok_or(DeviceError::AuthenticationFailed)?;
            entry.secure.authenticate_symmetric(request, &expected)?;
            entry.authenticated = true;
            entry.last_activity = Instant::now();
            self.sessions.insert(sid, entry);
            self.record_unlogged_authentication_if_full();
            Ok(Frame::response(
                CommandCode::AuthenticateSession as u8,
                Vec::new(),
            ))
        })();
        if self.should_audit(CommandCode::AuthenticateSession) {
            let result_code = result
                .as_ref()
                .err()
                .copied()
                .map_or(0, |error| error as u8);
            self.append_audit_entry(
                authorization,
                CommandCode::AuthenticateSession,
                request,
                result_code,
            );
        }
        result
    }

    fn session_message_with<F, O>(
        &mut self,
        request: &Frame,
        handler: &mut F,
        observer: &mut O,
    ) -> Result<Frame>
    where
        F: FnMut(SessionAuthorization, &Frame) -> Option<Frame>,
        O: FnMut(SessionAuthorization, &Frame, &Frame),
    {
        let sid = decode_request::<SessionMessageRequest>(&request.data)?
            .0
            .session_id;
        let mut entry = self
            .sessions
            .remove(&sid)
            .ok_or(DeviceError::InvalidSession)?;
        if !entry.authenticated {
            return Err(DeviceError::InvalidSession);
        }
        let inner = entry.secure.decrypt_request(request)?;
        entry.last_activity = Instant::now();
        let authorization_error = CommandCode::from_byte(inner.command)
            .and_then(CommandCode::required_session_capability)
            .and_then(|required| entry.authorization.require_capability(required).err());
        let handled_response = match authorization_error {
            Some(error) => Some(Frame::error(error)),
            None => handler(entry.authorization, &inner),
        };
        let handled_externally = handled_response.is_some();
        let response = handled_response.unwrap_or_else(|| {
            self.execute_inner_with_session(entry.authorization, &inner, Some(&mut entry.objects))
        });
        let response = if secure_response_fits(&response) {
            response
        } else {
            Frame::error(DeviceError::WrongLength)
        };
        observer(entry.authorization, &inner, &response);
        let closes_session = matches!(
            CommandCode::from_byte(inner.command),
            Some(CommandCode::CloseSession)
        ) || (matches!(
            CommandCode::from_byte(inner.command),
            Some(CommandCode::ResetDevice)
        ) && !handled_externally
            && response.command != crate::frame::ERROR_COMMAND);
        let outer = entry.secure.encrypt_response(&response)?;
        if !closes_session {
            self.sessions.insert(sid, entry);
        }
        Ok(outer)
    }

    fn get_device_public_key(&self, data: &[u8]) -> Result<Vec<u8>> {
        decode_request::<GetDevicePublicKeyRequest>(data)?;
        let SoftwarePublicKey::Ec {
            uncompressed: mut public,
            ..
        } = self.device_static_private.public_key()
        else {
            return Err(DeviceError::StorageFailed);
        };
        public[0] = AUTHENTICATION_ALGORITHM_EC_P256;
        Ok(public)
    }

    /// Execute an already decrypted session command under a snapshotted
    /// Authentication Key authorization context.
    pub fn execute_inner(&mut self, authorization: SessionAuthorization, request: &Frame) -> Frame {
        self.execute_inner_with_session(authorization, request, None)
    }

    fn execute_inner_with_session(
        &mut self,
        authorization: SessionAuthorization,
        request: &Frame,
        objects: Option<&mut SessionObjects>,
    ) -> Frame {
        let command = CommandCode::from_byte(request.command)
            .filter(|command| command.supported_by_firmware());
        let should_audit = command.is_some_and(|command| self.should_audit(command));
        if command.is_some_and(|command| {
            !command_is_meta(command)
                && !matches!(
                    command,
                    CommandCode::GetLogEntries | CommandCode::SetLogIndex
                )
        }) && self.options.force_audit != OPTION_OFF
            && self.audit.entries.len() >= usize::from(self.config.log_capacity)
        {
            return Frame::error(DeviceError::LogFull);
        }

        let result = self
            .execute_inner_result(authorization, request, objects)
            .and_then(|data| {
                if secure_response_data_fits(data.len()) {
                    Ok(data)
                } else {
                    Err(DeviceError::WrongLength)
                }
            });
        let result_code = result
            .as_ref()
            .err()
            .copied()
            .map_or(0, |error| error as u8);
        if let Some(command) = command {
            if should_audit {
                self.append_audit_entry(authorization, command, request, result_code);
            }
            if result.is_ok() && command_changes_persistent_state(command) {
                self.persistent_change = true;
            }
        }
        match result {
            Ok(data) => Frame::response(request.command, data),
            Err(error) => Frame::error(error),
        }
    }

    pub fn object(&self, key: ObjectKey) -> Option<&ObjectRecord> {
        self.objects.get(&key)
    }

    pub fn objects(&self) -> impl Iterator<Item = &ObjectRecord> {
        self.objects.values()
    }

    /// Install or replace an object as part of trusted device provisioning.
    /// Normal protocol clients must use the authorized PUT/GENERATE commands.
    pub fn provision_object(&mut self, object: ObjectRecord) -> Result<()> {
        let mut object = object;
        object.promote_private_material()?;
        object.validate()?;
        let key = object.info.key();
        self.sequence_history
            .record(key.id, u64::from(object.info.sequence));
        self.objects.insert(key, object);
        self.persistent_change = true;
        Ok(())
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    fn expire_inactive_sessions(&mut self, now: Instant) {
        self.sessions.retain(|_, session| {
            now.saturating_duration_since(session.last_activity) < SESSION_INACTIVITY_TIMEOUT
        });
    }

    /// Invalidate every volatile secure session without changing objects.
    pub fn clear_sessions(&mut self) {
        self.sessions.clear();
    }

    /// Encode durable device state. Secure sessions and transport counters are
    /// intentionally excluded, just as they are on a physical power cycle.
    pub fn persistent_state(&self) -> Result<Vec<u8>> {
        let objects = self
            .objects
            .values()
            .map(ObjectRecord::to_stored)
            .collect::<Result<Vec<_>>>()?;
        let device_static_private = self
            .device_static_private
            .serialized()
            .map_err(|_| DeviceError::StorageFailed)?
            .as_slice()
            .try_into()
            .map_err(|_| DeviceError::StorageFailed)?;
        let state = PersistentState {
            schema: PERSISTENT_STATE_SCHEMA.to_owned(),
            version: PERSISTENT_STATE_VERSION,
            config: self.config.clone(),
            objects,
            device_static_private,
            state_epoch: self.state_epoch,
            sequence_history: self.sequence_history.clone(),
            options: self.options.clone(),
            audit: self.audit.clone(),
        };
        let mut output = Vec::new();
        ciborium::into_writer(&state, &mut output).map_err(|_| DeviceError::StorageFailed)?;
        Ok(output)
    }

    /// Restore durable state for the configured serial number. Corrupt,
    /// foreign, or unsupported images are rejected rather than factory-reset.
    pub fn from_persistent_state(config: DeviceConfig, encoded: &[u8]) -> Result<Self> {
        let mut input = Cursor::new(encoded);
        let state: PersistentState =
            ciborium::from_reader(&mut input).map_err(|_| DeviceError::InvalidData)?;
        if input.position() != encoded.len() as u64
            || state.schema != PERSISTENT_STATE_SCHEMA
            || !matches!(state.version, 1 | 2 | PERSISTENT_STATE_VERSION)
            || state.config.serial != config.serial
            || state.audit.entries.len() > usize::from(config.log_capacity)
            || !valid_option_value(state.options.force_audit)
            || !valid_option_value(state.options.fips_mode)
            || state
                .options
                .command_audit
                .values()
                .chain(state.options.algorithm_toggle.values())
                .any(|value| !valid_option_value(*value))
        {
            return Err(DeviceError::InvalidData);
        }
        let device_static_private = SoftwareSigningKey::from_serialized_for_kind(
            KeyKind::Ec(EcCurve::P256),
            &state.device_static_private,
        )
        .map_err(|_| DeviceError::InvalidData)?;
        let stored_version = state.version;
        let sequence_history = state.sequence_history;
        if !sequence_history.validate() {
            return Err(DeviceError::InvalidData);
        }
        let mut objects = BTreeMap::new();
        for stored in state.objects {
            let stored_material_length = stored.material.len();
            let mut object = ObjectRecord::from_stored(stored)?;
            if stored_version < PERSISTENT_STATE_VERSION {
                let previous_length = match stored_version {
                    1 => stored_material_length,
                    2 => version_two_object_length(&object)?,
                    _ => return Err(DeviceError::InvalidData),
                };
                if usize::from(object.info.length) != previous_length {
                    return Err(DeviceError::InvalidData);
                }
                object.normalize_info_length()?;
            }
            object.validate()?;
            let key = object.info.key();
            if objects.insert(key, object).is_some() {
                return Err(DeviceError::InvalidData);
            }
        }
        Ok(Self {
            // Device identity and capabilities belong to the running virtual
            // firmware. Durable state supplies objects, options, and audit
            // history, but must not pin an upgraded instance to the firmware
            // configuration that originally created the state file.
            config,
            objects,
            sessions: BTreeMap::new(),
            device_static_private,
            state_epoch: state.state_epoch,
            sequence_history,
            options: state.options,
            audit: state.audit,
            persistent_change: false,
        })
    }

    /// Commit one pending durable transaction and advance its persisted epoch.
    pub fn take_persistent_change(&mut self) -> Result<bool> {
        if !self.persistent_change {
            return Ok(false);
        }
        self.state_epoch = self
            .state_epoch
            .checked_add(1)
            .ok_or(DeviceError::StorageFailed)?;
        self.persistent_change = false;
        Ok(true)
    }

    /// Return the ordering key carried by the next persistent snapshot.
    pub fn state_epoch(&self) -> u64 {
        self.state_epoch
    }

    fn execute_inner_result(
        &mut self,
        authorization: SessionAuthorization,
        request: &Frame,
        session_objects: Option<&mut SessionObjects>,
    ) -> Result<Vec<u8>> {
        if let Some(result) = self.execute_plain_or_authenticated(request) {
            return result;
        }
        let command = CommandCode::from_byte(request.command).ok_or(DeviceError::InvalidCommand)?;
        if !command.supported_by_firmware() {
            return Err(DeviceError::InvalidCommand);
        }
        self.authorize_command_request(authorization, command, &request.data)?;
        match command {
            CommandCode::CloseSession => {
                decode_request::<CloseSessionRequest>(&request.data).map(|_| Vec::new())
            }
            CommandCode::GetStorageInfo => {
                decode_request::<GetStorageInfoRequest>(&request.data)?;
                let used = self.objects.len() as u16;
                let free = MAX_OBJECTS.saturating_sub(self.objects.len()) as u16;
                Ok([MAX_OBJECTS as u16, free, 1024, 1024 - used, 126]
                    .into_iter()
                    .flat_map(u16::to_be_bytes)
                    .collect())
            }
            CommandCode::GetPseudoRandom => {
                let length =
                    usize::from(decode_request::<GetPseudoRandomRequest>(&request.data)?.length);
                let mut output = vec![0; length];
                getrandom::fill(&mut output).map_err(|_| DeviceError::StorageFailed)?;
                Ok(output)
            }
            CommandCode::ListObjects => self.list_objects(authorization, &request.data),
            CommandCode::GetObjectInfo => {
                let key = decode_request::<GetObjectInfoRequest>(&request.data)?.0.key;
                let object = self.objects.get(&key).ok_or(DeviceError::ObjectNotFound)?;
                authorization.require_visible(&object.info)?;
                let mut info = object.info.clone();
                info.capabilities.retain_firmware_supported();
                info.delegated_capabilities.retain_firmware_supported();
                Ok(info.encode().to_vec())
            }
            CommandCode::GetLogEntries => self.get_log_entries(&request.data),
            CommandCode::SetLogIndex => self.set_log_index(&request.data),
            CommandCode::SetOption => self.set_option(&request.data),
            CommandCode::GetOption => self.get_option(&request.data),
            CommandCode::PutAuthenticationKey => {
                self.put_authentication_key(authorization, &request.data)
            }
            CommandCode::ChangeAuthenticationKey => self.change_authentication_key(&request.data),
            CommandCode::PutOpaque => self.put_opaque(authorization, &request.data),
            CommandCode::PutAsymmetricKey => {
                self.put_asymmetric_key(authorization, &request.data, false)
            }
            CommandCode::GenerateAsymmetricKey => {
                self.put_asymmetric_key(authorization, &request.data, true)
            }
            CommandCode::GetPublicKey => self.get_public_key(authorization, &request.data),
            CommandCode::SignAttestationCertificate => {
                self.sign_attestation_certificate(authorization, &request.data)
            }
            CommandCode::SignPkcs1 => self.sign_pkcs1(authorization, &request.data),
            CommandCode::SignPss => self.sign_pss(authorization, &request.data),
            CommandCode::SignEcdsa => self.sign_ecdsa(authorization, &request.data),
            CommandCode::SignEddsa => self.sign_eddsa(authorization, &request.data),
            CommandCode::SignMlDsa => self.sign_ml_dsa(authorization, &request.data),
            CommandCode::EncapsulateMlKem => self.encapsulate_ml_kem(authorization, &request.data),
            CommandCode::DecapsulateMlKem => self.decapsulate_ml_kem(authorization, &request.data),
            CommandCode::DeriveEcdh => self.derive_ecdh(authorization, &request.data),
            CommandCode::DeriveEcdhKdf => self.derive_ecdh_kdf(authorization, &request.data),
            CommandCode::SessionObject => self.session_object_command(
                authorization,
                session_objects.ok_or(DeviceError::InvalidSession)?,
                &request.data,
            ),
            CommandCode::DecryptPkcs1 => self.decrypt_pkcs1(authorization, &request.data),
            CommandCode::DecryptOaep => self.decrypt_oaep(authorization, &request.data),
            CommandCode::PutHmacKey => self.put_hmac_key(authorization, &request.data, false),
            CommandCode::GenerateHmacKey => self.put_hmac_key(authorization, &request.data, true),
            CommandCode::SignHmac => self.sign_hmac(authorization, &request.data),
            CommandCode::VerifyHmac => self.verify_hmac(authorization, &request.data),
            CommandCode::PutWrapKey => self.put_wrap_key(authorization, &request.data, false),
            CommandCode::GenerateWrapKey => self.put_wrap_key(authorization, &request.data, true),
            CommandCode::PutPublicWrapKey => self.put_public_wrap_key(authorization, &request.data),
            CommandCode::WrapData => self.wrap_data(authorization, &request.data),
            CommandCode::UnwrapData => self.unwrap_data(authorization, &request.data),
            CommandCode::ExportWrapped => self.export_wrapped(authorization, &request.data),
            CommandCode::ImportWrapped => self.import_wrapped(authorization, &request.data),
            CommandCode::GetRsaWrappedKey => {
                self.export_rsa_wrapped(authorization, &request.data, true)
            }
            CommandCode::PutRsaWrappedKey => self.put_rsa_wrapped_key(authorization, &request.data),
            CommandCode::ExportRsaWrapped => {
                self.export_rsa_wrapped(authorization, &request.data, false)
            }
            CommandCode::ImportRsaWrapped => self.import_rsa_wrapped(authorization, &request.data),
            CommandCode::PutSymmetricKey => {
                self.put_symmetric_key(authorization, &request.data, false)
            }
            CommandCode::GenerateSymmetricKey => {
                self.put_symmetric_key(authorization, &request.data, true)
            }
            CommandCode::EncryptEcb => self.crypt_aes_ecb(authorization, &request.data, true),
            CommandCode::DecryptEcb => self.crypt_aes_ecb(authorization, &request.data, false),
            CommandCode::EncryptCbc => self.crypt_aes_cbc(authorization, &request.data, true),
            CommandCode::DecryptCbc => self.crypt_aes_cbc(authorization, &request.data, false),
            CommandCode::PutOtpAeadKey => {
                self.put_otp_aead_key(authorization, &request.data, false)
            }
            CommandCode::GenerateOtpAeadKey => {
                self.put_otp_aead_key(authorization, &request.data, true)
            }
            CommandCode::CreateOtpAead => self.create_otp_aead(authorization, &request.data),
            CommandCode::RandomizeOtpAead => self.randomize_otp_aead(authorization, &request.data),
            CommandCode::DecryptOtp => self.decrypt_otp(authorization, &request.data),
            CommandCode::RewrapOtpAead => self.rewrap_otp_aead(authorization, &request.data),
            CommandCode::PutTemplate => self.put_template(authorization, &request.data),
            CommandCode::GetTemplate => self.get_template(&request.data),
            CommandCode::GetOpaque => {
                let id = decode_request::<GetOpaqueRequest>(&request.data)?.id;
                let object = self
                    .objects
                    .get(&ObjectKey {
                        object_type: ObjectType::Opaque,
                        id,
                    })
                    .ok_or(DeviceError::ObjectNotFound)?;
                match &object.material {
                    ObjectMaterial::Opaque(data) => Ok(data.clone()),
                    _ => Err(DeviceError::InvalidData),
                }
            }
            CommandCode::DeleteObject => {
                let key = decode_request::<DeleteObjectRequest>(&request.data)?.0.key;
                if key.object_type == ObjectType::AuthenticationKey
                    && key.id == authorization.authentication_key_id
                {
                    // The current session remains valid, but future sessions
                    // cannot use the deleted Authentication Key.
                }
                self.objects.remove(&key);
                Ok(Vec::new())
            }
            CommandCode::ResetDevice => {
                decode_request::<ResetDeviceRequest>(&request.data)?;
                let renewed_device_static_private =
                    SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256))
                        .map_err(|_| DeviceError::StorageFailed)?;
                self.objects.clear();
                self.sequence_history.clear();
                self.sessions.clear();
                self.device_static_private = renewed_device_static_private;
                self.options = DeviceOptions::default();
                self.audit = AuditState {
                    next_number: 1,
                    ..AuditState::default()
                };
                self.install_factory_authentication_key();
                Ok(Vec::new())
            }
            CommandCode::BlinkDevice => {
                let request = decode_request::<BlinkDeviceRequest>(&request.data)?;
                let _duration = request.duration;
                Ok(Vec::new())
            }
            _ => Err(DeviceError::InvalidCommand),
        }
    }

    fn authorize_command_request(
        &self,
        authorization: SessionAuthorization,
        command: CommandCode,
        data: &[u8],
    ) -> Result<()> {
        if let Some(required) = command.required_session_capability() {
            authorization.require_capability(required)?;
        }

        let authorize = |object_type, id, capability| {
            self.authorize_object(authorization, ObjectKey { object_type, id }, capability)
        };
        match command {
            CommandCode::PutOpaque => {
                let request = decode_request::<PutOpaqueRequest>(data)?;
                let id = request.header.requested_id;
                if id != 0
                    && self.objects.contains_key(&ObjectKey {
                        object_type: ObjectType::Opaque,
                        id,
                    })
                {
                    authorize(ObjectType::Opaque, id, Capability::PutOpaque)
                } else {
                    Ok(())
                }
            }
            CommandCode::GetOpaque => {
                let request = decode_request::<GetOpaqueRequest>(data)?;
                self.require_object_visible(
                    authorization,
                    ObjectKey {
                        object_type: ObjectType::Opaque,
                        id: request.id,
                    },
                )
            }
            CommandCode::GetTemplate => {
                let request = decode_request::<GetTemplateRequest>(data)?;
                authorize(ObjectType::Template, request.id, Capability::GetTemplate)
            }
            CommandCode::ChangeAuthenticationKey => {
                let request = decode_request::<ChangeAuthenticationKeyRequest>(data)?;
                if request.id != authorization.authentication_key_id {
                    return Err(DeviceError::InvalidId);
                }
                authorize(
                    ObjectType::AuthenticationKey,
                    request.id,
                    Capability::ChangeAuthenticationKey,
                )
            }
            CommandCode::SignPkcs1 => {
                let request = decode_request::<SignPkcs1Request>(data)?;
                authorize(ObjectType::AsymmetricKey, request.id, Capability::SignPkcs)
            }
            CommandCode::SignPss => {
                let request = decode_request::<SignPssRequest>(data)?;
                authorize(ObjectType::AsymmetricKey, request.id, Capability::SignPss)
            }
            CommandCode::SignEcdsa => {
                let request = decode_request::<SignEcdsaRequest>(data)?;
                authorize(ObjectType::AsymmetricKey, request.id, Capability::SignEcdsa)
            }
            CommandCode::SignEddsa => {
                let request = decode_request::<SignEddsaRequest>(data)?;
                authorize(ObjectType::AsymmetricKey, request.id, Capability::SignEddsa)
            }
            CommandCode::SignMlDsa => {
                let request = decode_request::<SignMlDsaRequest>(data)?;
                authorize(ObjectType::AsymmetricKey, request.id, Capability::SignMlDsa)
            }
            CommandCode::EncapsulateMlKem => {
                let request = decode_request::<EncapsulateMlKemRequest>(data)?;
                authorize(
                    ObjectType::AsymmetricKey,
                    request.id,
                    Capability::EncapsulateMlKem,
                )
            }
            CommandCode::DecapsulateMlKem => {
                let request = decode_request::<DecapsulateMlKemRequest>(data)?;
                authorize(
                    ObjectType::AsymmetricKey,
                    request.id,
                    Capability::DecapsulateMlKem,
                )
            }
            CommandCode::DeriveEcdh => {
                let request = decode_request::<DeriveEcdhRequest>(data)?;
                authorize(
                    ObjectType::AsymmetricKey,
                    request.id,
                    Capability::DeriveEcdh,
                )
            }
            CommandCode::DeriveEcdhKdf => {
                let request = decode_request::<DeriveEcdhKdfRequest>(data)?;
                authorize(
                    ObjectType::AsymmetricKey,
                    request.id,
                    Capability::DeriveEcdhKdf,
                )
            }
            CommandCode::DecryptPkcs1 => {
                let request = decode_request::<DecryptPkcs1Request>(data)?;
                authorize(
                    ObjectType::AsymmetricKey,
                    request.id,
                    Capability::DecryptPkcs,
                )
            }
            CommandCode::DecryptOaep => {
                let request = decode_request::<DecryptOaepRequest>(data)?;
                authorize(
                    ObjectType::AsymmetricKey,
                    request.id,
                    Capability::DecryptOaep,
                )
            }
            CommandCode::SignHmac => {
                let request = decode_request::<SignHmacRequest>(data)?;
                authorize(ObjectType::HmacKey, request.id, Capability::SignHmac)
            }
            CommandCode::VerifyHmac => {
                let request = decode_request::<VerifyHmacRequest>(data)?;
                authorize(ObjectType::HmacKey, request.id, Capability::VerifyHmac)
            }
            CommandCode::WrapData => {
                let request = decode_request::<WrapDataRequest>(data)?;
                authorize(ObjectType::WrapKey, request.id, Capability::WrapData)
            }
            CommandCode::UnwrapData => {
                let request = decode_request::<UnwrapDataRequest>(data)?;
                authorize(ObjectType::WrapKey, request.id, Capability::UnwrapData)
            }
            CommandCode::EncryptEcb => {
                let request = decode_request::<EncryptEcbRequest>(data)?;
                authorize(ObjectType::SymmetricKey, request.id, Capability::EncryptEcb)
            }
            CommandCode::DecryptEcb => {
                let request = decode_request::<DecryptEcbRequest>(data)?;
                authorize(ObjectType::SymmetricKey, request.id, Capability::DecryptEcb)
            }
            CommandCode::EncryptCbc => {
                let request = decode_request::<EncryptCbcRequest>(data)?.0;
                authorize(ObjectType::SymmetricKey, request.id, Capability::EncryptCbc)
            }
            CommandCode::DecryptCbc => {
                let request = decode_request::<DecryptCbcRequest>(data)?.0;
                authorize(ObjectType::SymmetricKey, request.id, Capability::DecryptCbc)
            }
            CommandCode::CreateOtpAead => {
                let request = decode_request::<CreateOtpAeadRequest>(data)?;
                authorize(
                    ObjectType::OtpAeadKey,
                    request.id,
                    Capability::CreateOtpAead,
                )
            }
            CommandCode::RandomizeOtpAead => {
                let request = decode_request::<RandomizeOtpAeadRequest>(data)?;
                authorize(
                    ObjectType::OtpAeadKey,
                    request.id,
                    Capability::RandomizeOtpAead,
                )
            }
            CommandCode::DecryptOtp => {
                let request = decode_request::<DecryptOtpRequest>(data)?;
                authorize(ObjectType::OtpAeadKey, request.id, Capability::DecryptOtp)
            }
            CommandCode::RewrapOtpAead => {
                let request = decode_request::<RewrapOtpAeadRequest>(data)?;
                authorize(
                    ObjectType::OtpAeadKey,
                    request.from_id,
                    Capability::RewrapFromOtpAeadKey,
                )?;
                authorize(
                    ObjectType::OtpAeadKey,
                    request.to_id,
                    Capability::RewrapToOtpAeadKey,
                )
            }
            CommandCode::ExportWrapped => {
                let request = decode_request::<ExportWrappedRequest>(data)?;
                self.authorize_wrapped_export(
                    authorization,
                    ObjectType::WrapKey,
                    request.wrap_id,
                    request.target,
                )
            }
            CommandCode::GetRsaWrappedKey => {
                let request = decode_request::<GetRsaWrappedKeyRequest>(data)?.0;
                self.authorize_wrapped_export(
                    authorization,
                    ObjectType::PublicWrapKey,
                    request.wrap_id,
                    request.target,
                )
            }
            CommandCode::ExportRsaWrapped => {
                let request = decode_request::<ExportRsaWrappedRequest>(data)?.0;
                self.authorize_wrapped_export(
                    authorization,
                    ObjectType::PublicWrapKey,
                    request.wrap_id,
                    request.target,
                )
            }
            CommandCode::ImportWrapped => {
                let request = decode_request::<ImportWrappedRequest>(data)?;
                authorize(
                    ObjectType::WrapKey,
                    request.wrap_id,
                    Capability::ImportWrapped,
                )
            }
            CommandCode::ImportRsaWrapped => {
                let request = decode_request::<ImportRsaWrappedRequest>(data)?;
                authorize(
                    ObjectType::WrapKey,
                    request.wrap_id,
                    Capability::ImportWrapped,
                )
            }
            CommandCode::PutRsaWrappedKey => {
                let request = decode_request::<PutRsaWrappedKeyRequest>(data)?;
                authorize(
                    ObjectType::WrapKey,
                    request.wrap_id,
                    Capability::ImportWrapped,
                )
            }
            CommandCode::SignAttestationCertificate => {
                let request = decode_request::<SignAttestationCertificateRequest>(data)?;
                if request.target_id != 0 {
                    self.require_object_visible(
                        authorization,
                        ObjectKey {
                            object_type: ObjectType::AsymmetricKey,
                            id: request.target_id,
                        },
                    )?;
                }
                if request.attesting_id != 0 {
                    self.authorize_object(
                        authorization,
                        ObjectKey {
                            object_type: ObjectType::AsymmetricKey,
                            id: request.attesting_id,
                        },
                        Capability::SignAttestationCertificate,
                    )?;
                    if self.objects.contains_key(&ObjectKey {
                        object_type: ObjectType::Opaque,
                        id: request.attesting_id,
                    }) {
                        self.require_object_visible(
                            authorization,
                            ObjectKey {
                                object_type: ObjectType::Opaque,
                                id: request.attesting_id,
                            },
                        )?;
                    }
                }
                Ok(())
            }
            CommandCode::GetObjectInfo => {
                let request = decode_request::<GetObjectInfoRequest>(data)?.0;
                self.require_object_visible(authorization, request.key)
            }
            CommandCode::GetPublicKey => {
                let request = decode_request::<GetPublicKeyRequest>(data)?;
                self.require_object_visible(
                    authorization,
                    ObjectKey {
                        object_type: request.object_type,
                        id: request.id,
                    },
                )
            }
            CommandCode::DeleteObject => {
                let request = decode_request::<DeleteObjectRequest>(data)?.0;
                let object = self
                    .objects
                    .get(&request.key)
                    .ok_or(DeviceError::ObjectNotFound)?;
                authorization.authorize_delete(&object.info)
            }
            _ => Ok(()),
        }
    }

    fn authorize_object(
        &self,
        authorization: SessionAuthorization,
        key: ObjectKey,
        capability: Capability,
    ) -> Result<()> {
        let object = self.objects.get(&key).ok_or(DeviceError::ObjectNotFound)?;
        authorization.authorize_use(&object.info, capability, capability)
    }

    fn require_object_visible(
        &self,
        authorization: SessionAuthorization,
        key: ObjectKey,
    ) -> Result<()> {
        let object = self.objects.get(&key).ok_or(DeviceError::ObjectNotFound)?;
        authorization.require_visible(&object.info)
    }

    fn authorize_wrapped_export(
        &self,
        authorization: SessionAuthorization,
        wrap_key_type: ObjectType,
        wrap_id: u16,
        target_key: ObjectKey,
    ) -> Result<()> {
        let wrap_key = self
            .objects
            .get(&ObjectKey {
                object_type: wrap_key_type,
                id: wrap_id,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        let target = self
            .objects
            .get(&target_key)
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.authorize_wrapped_export(target, wrap_key)
    }

    fn get_device_info(&self, data: &[u8]) -> Result<Vec<u8>> {
        match decode_request::<GetDeviceInfoRequest>(data)?.selector {
            None => {
                let algorithms = self.enabled_algorithms();
                let mut output = Vec::with_capacity(9 + algorithms.len());
                output.extend_from_slice(&self.config.version);
                output.extend_from_slice(&self.config.serial.to_be_bytes());
                output.push(self.config.log_capacity);
                output.push(self.audit.entries.len().try_into().unwrap_or(u8::MAX));
                output.extend_from_slice(&algorithms);
                Ok(output)
            }
            Some(1) => Ok(self.config.part_number.to_vec()),
            Some(_) => Err(DeviceError::InvalidData),
        }
    }

    fn get_log_entries(&self, data: &[u8]) -> Result<Vec<u8>> {
        decode_request::<GetLogEntriesRequest>(data)?;
        let mut output = Vec::with_capacity(5 + self.audit.entries.len() * 32);
        output.extend_from_slice(&self.audit.unlogged_boot.to_be_bytes());
        output.extend_from_slice(&self.audit.unlogged_authentication.to_be_bytes());
        output.push(self.audit.entries.len().try_into().unwrap_or(u8::MAX));
        for entry in &self.audit.entries {
            entry.encode(&mut output);
        }
        Ok(output)
    }

    fn set_log_index(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let index = decode_request::<SetLogIndexRequest>(data)?.index;
        self.audit.entries.retain(|entry| entry.number > index);
        Ok(Vec::new())
    }

    fn get_option(&self, data: &[u8]) -> Result<Vec<u8>> {
        let option = decode_request::<GetOptionRequest>(data)?.option;
        match option {
            OPTION_FORCE_AUDIT => Ok(vec![self.options.force_audit]),
            OPTION_COMMAND_AUDIT => {
                let mut output = Vec::new();
                for command in 0..=u8::MAX {
                    if CommandCode::from_byte(command)
                        .is_some_and(CommandCode::supported_by_firmware)
                    {
                        output.extend_from_slice(&[
                            command,
                            self.options
                                .command_audit
                                .get(&command)
                                .copied()
                                .unwrap_or(OPTION_OFF),
                        ]);
                    }
                }
                Ok(output)
            }
            OPTION_ALGORITHM_TOGGLE => {
                let mut output = Vec::with_capacity(self.config.algorithms.len() * 2);
                for algorithm in self.config.algorithms.iter().filter(|algorithm| {
                    Algorithm::from_byte(**algorithm).is_some_and(Algorithm::supported_by_firmware)
                }) {
                    output.extend_from_slice(&[
                        *algorithm,
                        self.options
                            .algorithm_toggle
                            .get(algorithm)
                            .copied()
                            .unwrap_or(OPTION_ON),
                    ]);
                }
                Ok(output)
            }
            OPTION_FIPS_MODE => Ok(vec![self.options.fips_mode]),
            _ => Err(DeviceError::InvalidData),
        }
    }

    fn set_option(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<SetOptionRequest>(data)?;
        let option = request.option;
        let values = request.values;
        match option {
            OPTION_FORCE_AUDIT => {
                let &[value] = values else {
                    return Err(DeviceError::WrongLength);
                };
                set_option_value(&mut self.options.force_audit, value)?;
            }
            OPTION_COMMAND_AUDIT => {
                if values.is_empty() || !values.len().is_multiple_of(2) {
                    return Err(DeviceError::WrongLength);
                }
                let mut updated = self.options.command_audit.clone();
                for pair in values.as_chunks::<2>().0 {
                    let Some(command) = CommandCode::from_byte(pair[0])
                        .filter(|command| command.supported_by_firmware())
                    else {
                        return Err(DeviceError::InvalidData);
                    };
                    if !valid_option_value(pair[1]) {
                        return Err(DeviceError::InvalidData);
                    }
                    if command == CommandCode::SessionMessage && pair[1] != OPTION_OFF {
                        return Err(DeviceError::InvalidData);
                    }
                    if updated.get(&pair[0]) == Some(&OPTION_FIX) && pair[1] != OPTION_FIX {
                        return Err(DeviceError::InsufficientPermissions);
                    }
                    updated.insert(pair[0], pair[1]);
                }
                self.options.command_audit = updated;
            }
            OPTION_ALGORITHM_TOGGLE => {
                self.require_fresh_device_for_algorithm_options()?;
                if values.is_empty() || !values.len().is_multiple_of(2) {
                    return Err(DeviceError::WrongLength);
                }
                let mut updated = self.options.algorithm_toggle.clone();
                for pair in values.as_chunks::<2>().0 {
                    if !self.config.algorithms.contains(&pair[0])
                        || !Algorithm::from_byte(pair[0])
                            .is_some_and(Algorithm::supported_by_firmware)
                        || !valid_option_value(pair[1])
                    {
                        return Err(DeviceError::InvalidData);
                    }
                    if updated.get(&pair[0]) == Some(&OPTION_FIX) && pair[1] != OPTION_FIX {
                        return Err(DeviceError::InsufficientPermissions);
                    }
                    updated.insert(pair[0], pair[1]);
                }
                self.options.algorithm_toggle = updated;
            }
            OPTION_FIPS_MODE => {
                self.require_fresh_device_for_algorithm_options()?;
                let &[value] = values else {
                    return Err(DeviceError::WrongLength);
                };
                set_option_value(&mut self.options.fips_mode, value)?;
            }
            _ => return Err(DeviceError::InvalidData),
        }
        Ok(Vec::new())
    }

    fn require_fresh_device_for_algorithm_options(&self) -> Result<()> {
        let factory_key = ObjectKey {
            object_type: ObjectType::AuthenticationKey,
            id: 1,
        };
        if self.objects.len() == 1 && self.objects.contains_key(&factory_key) {
            Ok(())
        } else {
            Err(DeviceError::InsufficientPermissions)
        }
    }

    fn enabled_algorithms(&self) -> Vec<u8> {
        self.config
            .algorithms
            .iter()
            .copied()
            .filter(|algorithm| self.algorithm_enabled(*algorithm))
            .collect()
    }

    fn algorithm_enabled(&self, algorithm: u8) -> bool {
        Algorithm::from_byte(algorithm).is_some_and(Algorithm::supported_by_firmware)
            && self.config.algorithms.contains(&algorithm)
            && self
                .options
                .algorithm_toggle
                .get(&algorithm)
                .copied()
                .unwrap_or(OPTION_ON)
                != OPTION_OFF
            && !(self.options.fips_mode != OPTION_OFF && fips_disallowed_algorithm(algorithm))
    }

    fn require_algorithm_enabled(&self, algorithm: u8) -> Result<()> {
        if self.algorithm_enabled(algorithm) {
            Ok(())
        } else {
            Err(DeviceError::InvalidData)
        }
    }

    fn should_audit(&self, command: CommandCode) -> bool {
        command_can_be_audited(command)
            && self
                .options
                .command_audit
                .get(&(command as u8))
                .copied()
                .unwrap_or(OPTION_OFF)
                != OPTION_OFF
    }

    fn append_audit_entry(
        &mut self,
        authorization: SessionAuthorization,
        command: CommandCode,
        request: &Frame,
        result: u8,
    ) {
        if self.audit.entries.len() >= usize::from(self.config.log_capacity) {
            return;
        }
        let (target_key, second_key) = if command == CommandCode::AuthenticateSession {
            (authorization.authentication_key_id, 0)
        } else {
            audit_key_ids(command, &request.data)
        };
        let mut entry = AuditEntry {
            number: self.audit.next_number,
            command: command as u8,
            length: request.data.len().try_into().unwrap_or(u16::MAX),
            session_key: authorization.authentication_key_id,
            target_key,
            second_key,
            result,
            systick: self.audit.systick,
            digest: [0; 16],
        };
        let mut encoded = Vec::with_capacity(32);
        entry.encode(&mut encoded);
        let mut digest_input = Vec::with_capacity(32);
        digest_input.extend_from_slice(&encoded[..16]);
        digest_input.extend_from_slice(&self.audit.previous_digest);
        entry.digest.copy_from_slice(
            &software_key_core::digest::HashAlgorithm::Sha256.digest(&digest_input)[..16],
        );
        self.audit.previous_digest = entry.digest;
        self.audit.next_number = self.audit.next_number.wrapping_add(1).max(1);
        self.audit.systick = self.audit.systick.wrapping_add(1);
        self.audit.entries.push(entry);
        self.persistent_change = true;
    }

    fn record_unlogged_authentication_if_full(&mut self) {
        if self.options.force_audit != OPTION_OFF
            && self.audit.entries.len() >= usize::from(self.config.log_capacity)
        {
            self.audit.unlogged_authentication =
                self.audit.unlogged_authentication.saturating_add(1);
            self.persistent_change = true;
        }
    }

    fn list_objects(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let filters = decode_request::<ListObjectsRequest>(data)
            .map_err(|error| match error {
                DeviceError::WrongLength => DeviceError::InvalidData,
                error => error,
            })?
            .filters;
        let mut output = Vec::new();
        for object in self.objects.values() {
            if authorization.can_see(&object.info) && filters.matches(&object.info) {
                output.extend_from_slice(&object.info.id.to_be_bytes());
                output.push(object.info.object_type as u8);
                output.push(object.info.sequence);
            }
        }
        Ok(output)
    }

    fn put_opaque(&mut self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<PutOpaqueRequest>(data)?;
        let header = request.header;
        self.require_algorithm_enabled(header.algorithm)?;
        let requested_id = header.requested_id;
        let capabilities = header.capabilities;
        let domains = header.domains;
        let algorithm = header.algorithm;
        let label = trim_label(header.label);
        let material = request.material.to_vec();
        if algorithm != OPAQUE_DATA_ALGORITHM && material.is_empty() {
            return Err(DeviceError::InvalidData);
        }
        if requested_id != 0 {
            let key = ObjectKey {
                object_type: ObjectType::Opaque,
                id: requested_id,
            };
            if let Some(existing) = self.objects.get(&key) {
                if existing.info.capabilities != capabilities
                    || existing.info.domains != domains
                    || existing.info.algorithm != algorithm
                    || existing.info.label != label
                {
                    return Err(DeviceError::InvalidData);
                }
                let mut updated = existing.clone();
                updated.info.length =
                    u16::try_from(material.len()).map_err(|_| DeviceError::WrongLength)?;
                updated.material = ObjectMaterial::Opaque(material);
                self.write_object(updated)?;
                return Ok(requested_id.to_be_bytes().to_vec());
            }
        }
        let id = self.resolve_id(ObjectType::Opaque, requested_id)?;
        let info = ObjectInfo {
            capabilities,
            id,
            length: u16::try_from(material.len()).map_err(|_| DeviceError::WrongLength)?,
            domains,
            object_type: ObjectType::Opaque,
            algorithm,
            sequence: 0,
            origin: 2,
            label,
            delegated_capabilities: CapabilitySet::NONE,
        };
        authorization.authorize_create(&info, Capability::PutOpaque)?;
        let record = ObjectRecord {
            info,
            material: ObjectMaterial::Opaque(material),
        };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn put_authentication_key(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<PutAuthenticationKeyRequest>(data)?.0;
        let header = request.header;
        let algorithm = header.algorithm;
        self.require_algorithm_enabled(algorithm)?;
        let key_length = authentication_key_length(algorithm)?;
        if request.material.len() != key_length {
            return Err(DeviceError::WrongLength);
        }
        let id = self.resolve_id(ObjectType::AuthenticationKey, header.requested_id)?;
        let info = ObjectInfo {
            capabilities: header.capabilities,
            id,
            length: (key_length + 8) as u16,
            domains: header.domains,
            object_type: ObjectType::AuthenticationKey,
            algorithm,
            sequence: 0,
            origin: 2,
            label: trim_label(header.label),
            delegated_capabilities: request.delegated_capabilities,
        };
        authorization.authorize_create(&info, Capability::PutAuthenticationKey)?;
        let material = parse_authentication_key_material(algorithm, request.material)?;
        let record = ObjectRecord {
            info,
            material: ObjectMaterial::Authentication(material),
        };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn put_asymmetric_key(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
        generate: bool,
    ) -> Result<Vec<u8>> {
        let (header, supplied) = if generate {
            let request = decode_request::<GenerateAsymmetricKeyRequest>(data)?;
            (request.header, request.material)
        } else {
            let request = decode_request::<PutAsymmetricKeyRequest>(data)?;
            (request.header, request.material)
        };
        if generate && !supplied.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let algorithm = Algorithm::from_byte(header.algorithm).ok_or(DeviceError::InvalidData)?;
        self.require_algorithm_enabled(algorithm as u8)?;
        let expected_length = algorithm
            .asymmetric_key_length()
            .ok_or(DeviceError::InvalidData)?;
        let material = asymmetric_key_material(algorithm, generate, supplied)?;
        if material.len() != expected_length {
            return Err(DeviceError::InvalidData);
        }
        let id = self.resolve_id(ObjectType::AsymmetricKey, header.requested_id)?;
        let capability = if generate {
            Capability::GenerateAsymmetricKey
        } else {
            Capability::PutAsymmetricKey
        };
        let info = ObjectInfo {
            capabilities: header.capabilities,
            id,
            length: algorithm
                .asymmetric_object_length()
                .ok_or(DeviceError::InvalidData)? as u16,
            domains: header.domains,
            object_type: ObjectType::AsymmetricKey,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: if generate { 1 } else { 2 },
            label: trim_label(header.label),
            delegated_capabilities: CapabilitySet::NONE,
        };
        authorization.authorize_create(&info, capability)?;
        let record = ObjectRecord { info, material };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn get_public_key(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<GetPublicKeyRequest>(data)?;
        let id = request.id;
        let object_type = request.object_type;
        if !matches!(
            object_type,
            ObjectType::AsymmetricKey
                | ObjectType::AuthenticationKey
                | ObjectType::WrapKey
                | ObjectType::PublicWrapKey
        ) {
            return Err(DeviceError::InvalidData);
        }
        let object = self
            .objects
            .get(&ObjectKey { object_type, id })
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.require_visible(&object.info)?;
        let mut output = vec![object.info.algorithm];
        if object.info.object_type == ObjectType::AuthenticationKey {
            match &object.material {
                ObjectMaterial::Authentication(AuthenticationKeyMaterial::Asymmetric(public)) => {
                    output.extend_from_slice(public)
                }
                _ => return Err(DeviceError::InvalidData),
            }
        } else if object.info.object_type == ObjectType::PublicWrapKey {
            match &object.material {
                ObjectMaterial::Public(public) => output.extend_from_slice(public),
                _ => return Err(DeviceError::InvalidData),
            }
        } else if let ObjectMaterial::MlKemKey(key) = &object.material {
            output.extend_from_slice(&key.public_key());
        } else if matches!(
            Algorithm::from_byte(object.info.algorithm),
            Some(Algorithm::X25519 | Algorithm::X448)
        ) {
            output.extend_from_slice(&montgomery_key(object)?.public_key());
        } else {
            match signing_key(object)?.public_key() {
                SoftwarePublicKey::Ec { uncompressed, .. } => {
                    output.extend_from_slice(&uncompressed[1..]);
                }
                SoftwarePublicKey::Edwards {
                    curve: EdwardsCurve::Ed25519,
                    public_key,
                } => output.extend_from_slice(&public_key),
                SoftwarePublicKey::Edwards {
                    curve: EdwardsCurve::Ed448,
                    public_key,
                } => output.extend_from_slice(&public_key),
                SoftwarePublicKey::Rsa { modulus, .. } => output.extend_from_slice(&modulus),
                SoftwarePublicKey::MlDsa { public_key, .. } => {
                    output.extend_from_slice(&public_key)
                }
            }
        }
        Ok(output)
    }

    fn sign_attestation_certificate(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<SignAttestationCertificateRequest>(data)?;
        let target_id = request.target_id;
        let attesting_id = request.attesting_id;
        let (target_spki, target_info) = if target_id == 0 {
            let SoftwarePublicKey::Ec {
                uncompressed: public,
                ..
            } = self.device_static_private.public_key()
            else {
                return Err(DeviceError::StorageFailed);
            };
            (
                subject_public_key_info(&SoftwarePublicKey::Ec {
                    curve: EcCurve::P256,
                    uncompressed: public,
                })
                .map_err(|_| DeviceError::InvalidData)?,
                ObjectInfo {
                    capabilities: CapabilitySet::NONE,
                    id: 0,
                    length: Algorithm::EcP256.asymmetric_object_length().unwrap() as u16,
                    domains: 0,
                    object_type: ObjectType::AsymmetricKey,
                    algorithm: Algorithm::EcP256 as u8,
                    sequence: 0,
                    origin: 0,
                    label: b"Virtual YubiHSM device key".to_vec(),
                    delegated_capabilities: CapabilitySet::NONE,
                },
            )
        } else {
            let target = self.asymmetric_object(authorization, target_id)?;
            if target.info.origin & 1 == 0 {
                return Err(DeviceError::InvalidData);
            }
            self.require_algorithm_enabled(target.info.algorithm)?;
            (object_subject_public_key_info(target)?, target.info.clone())
        };
        let (attesting_private, issuer) = if attesting_id == 0 {
            (
                &self.device_static_private,
                format!("CN=Virtual YubiHSM {} Attestation", self.config.serial),
            )
        } else {
            let attesting = self.asymmetric_object(authorization, attesting_id)?;
            if attesting.info.algorithm != Algorithm::EcP256 as u8 {
                return Err(DeviceError::InvalidData);
            }
            (
                signing_key(attesting)?,
                format!("CN=Virtual YubiHSM Attestation Key {attesting_id}"),
            )
        };
        let signer =
            CertificateSigner::from_key(attesting_private).map_err(|_| DeviceError::InvalidData)?;
        let mut subject = Name::from_str(&format!("CN=Virtual YubiHSM Key {target_id}"))
            .map_err(|_| DeviceError::InvalidData)?;
        let mut issuer = Name::from_str(&issuer).map_err(|_| DeviceError::InvalidData)?;
        let mut validity = Validity::from_now(Duration::from_secs(10 * 365 * 86_400))
            .map_err(|_| DeviceError::StorageFailed)?;
        let mut template_extensions = Vec::new();
        if attesting_id != 0
            && let Some(template) = self.objects.get(&ObjectKey {
                object_type: ObjectType::Opaque,
                id: attesting_id,
            })
        {
            authorization.require_visible(&template.info)?;
            if template.info.algorithm != Algorithm::OpaqueX509Certificate as u8 {
                return Err(DeviceError::InvalidData);
            }
            let ObjectMaterial::Opaque(encoded) = &template.material else {
                return Err(DeviceError::InvalidData);
            };
            let certificate =
                x509_cert::Certificate::from_der(encoded).map_err(|_| DeviceError::InvalidData)?;
            let tbs = certificate.tbs_certificate();
            subject = tbs.subject().clone();
            issuer = tbs.issuer().clone();
            validity = *tbs.validity();
            template_extensions = tbs.extensions().cloned().unwrap_or_default();
        }
        let algorithm =
            Algorithm::from_byte(target_info.algorithm).ok_or(DeviceError::InvalidData)?;
        let profile = AttestationProfile {
            subject,
            issuer,
            key_agreement: matches!(
                algorithm,
                Algorithm::Ecdh | Algorithm::X25519 | Algorithm::X448
            ) || algorithm.is_weierstrass_key(),
            key_encipherment: algorithm.is_rsa_key(),
            template_extensions,
            metadata_extensions: attestation_metadata_extensions(&self.config, &target_info)?,
        };
        let mut serial = [0_u8; 8];
        serial[..4].copy_from_slice(&self.config.serial.to_be_bytes());
        serial[4..6].copy_from_slice(&target_id.to_be_bytes());
        serial[6..].copy_from_slice(&attesting_id.to_be_bytes());
        let builder = CertificateBuilder::new(
            profile,
            SerialNumber::new(&serial).map_err(|_| DeviceError::InvalidData)?,
            validity,
            target_spki,
        )
        .map_err(|_| DeviceError::InvalidData)?;
        let certificate = builder
            .build::<_, CertificateSignature>(&signer)
            .map_err(|_| DeviceError::StorageFailed)?;
        certificate.to_der().map_err(|_| DeviceError::StorageFailed)
    }

    fn sign_pkcs1(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<SignPkcs1Request>(data)?;
        if request.payload.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let object = self.asymmetric_object(authorization, request.id)?;
        let key = rsa_key(object)?;
        let payload = request.payload;
        let signature = match rsa_hash_from_digest_length(payload.len()) {
            Some(hash) => key.sign_rsa_pkcs1v15_digest(hash, payload),
            None => key.sign_rsa_pkcs1v15_payload(payload),
        };
        signature
            .map(|signature| signature.into_bytes())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn sign_pss(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<SignPssRequest>(data)?;
        if request.digest.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let object = self.asymmetric_object(authorization, request.id)?;
        let mgf_hash = rsa_mgf_hash(request.mgf_hash)?;
        let salt_length = usize::from(request.salt_length);
        let digest = request.digest;
        let hash = rsa_hash_from_digest_length(digest.len()).ok_or(DeviceError::WrongLength)?;
        rsa_key(object)?
            .sign_rsa_pss_digest(hash, mgf_hash, salt_length, digest)
            .map(|signature| signature.into_bytes())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn sign_ecdsa(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<SignEcdsaRequest>(data)?;
        if request.digest.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let object = self.asymmetric_object(authorization, request.id)?;
        let (algorithm, _) = asymmetric_key_algorithm(object.info.algorithm)?;
        if matches!(algorithm, SignatureScheme::Ed25519 | SignatureScheme::Ed448) {
            return Err(DeviceError::InvalidData);
        }
        let curve = algorithm.ec_curve().ok_or(DeviceError::InvalidData)?;
        signing_key(object)?
            .sign_prehash(algorithm, request.digest)
            .and_then(|signature| signature.to_ecdsa_der(curve))
            .map_err(|_| DeviceError::InvalidData)
    }

    /// key-id (BE), hedge mode (0 deterministic, 1 required, 2 preferred),
    /// context length (u8), context, message. Returns a raw FIPS 204 signature.
    fn sign_ml_dsa(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        use software_key_core::post_quantum::MlDsaRandomization;
        let request = decode_request::<SignMlDsaRequest>(data)?;
        let object = self.asymmetric_object(authorization, request.id)?;
        self.require_algorithm_enabled(object.info.algorithm)?;
        let mode = match request.mode {
            0 => MlDsaRandomization::Deterministic,
            1 => MlDsaRandomization::Randomized,
            2 => MlDsaRandomization::HedgePreferred,
            _ => return Err(DeviceError::InvalidData),
        };
        let SoftwareSigningKey::MlDsa(key) = signing_key(object)? else {
            return Err(DeviceError::InvalidData);
        };
        key.sign(request.message, request.context, mode)
            .map_err(|_| DeviceError::InvalidData)
    }

    /// key-id (BE). Returns ciphertext followed by the 32-byte shared secret.
    fn encapsulate_ml_kem(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<EncapsulateMlKemRequest>(data)?;
        let object = self.asymmetric_object(authorization, request.id)?;
        self.require_algorithm_enabled(object.info.algorithm)?;
        let ObjectMaterial::MlKemKey(key) = &object.material else {
            return Err(DeviceError::InvalidData);
        };
        let (mut ciphertext, secret) = software_key_core::post_quantum::ml_kem_encapsulate(
            key.parameter_set(),
            &key.public_key(),
        )
        .map_err(|_| DeviceError::InvalidData)?;
        ciphertext.extend_from_slice(&secret);
        Ok(ciphertext)
    }

    /// key-id (BE), ciphertext. Returns the 32-byte shared secret.
    fn decapsulate_ml_kem(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<DecapsulateMlKemRequest>(data)?;
        if request.ciphertext.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let object = self.asymmetric_object(authorization, request.id)?;
        self.require_algorithm_enabled(object.info.algorithm)?;
        let ObjectMaterial::MlKemKey(key) = &object.material else {
            return Err(DeviceError::InvalidData);
        };
        let ciphertext = request.ciphertext;
        if ciphertext.len() != key.parameter_set().ciphertext_length() {
            return Err(DeviceError::WrongLength);
        }
        key.decapsulate(ciphertext)
            .map(|secret| secret.to_vec())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn sign_eddsa(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<SignEddsaRequest>(data)?;
        let object = self.asymmetric_object(authorization, request.id)?;
        let scheme = match Algorithm::from_byte(object.info.algorithm) {
            Some(Algorithm::Ed25519) => SignatureScheme::Ed25519,
            Some(Algorithm::Ed448) => SignatureScheme::Ed448,
            _ => return Err(DeviceError::InvalidData),
        };
        signing_key(object)?
            .sign_message(scheme, request.message)
            .map(|signature| signature.into_bytes())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn derive_ecdh(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<DeriveEcdhRequest>(data)?;
        if request.peer_public.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let object = self.asymmetric_object(authorization, request.id)?;
        raw_ecdh_secret(object, request.peer_public).map(|secret| secret.to_vec())
    }

    /// Derive an ECDH secret, prefix it with caller-provided secret material,
    /// and apply ANSI X9.63 without exposing the raw ECDH result.
    ///
    /// Request encoding:
    ///
    /// ```text
    /// key id             u16
    /// X9.63 hash         u8   (1..=9; SHA-1 through SHA3-512)
    /// output length      u16
    /// peer public length u16
    /// prefix length      u16
    /// shared-info length u16
    /// peer public || prefix || shared-info
    /// ```
    fn derive_ecdh_kdf(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<DeriveEcdhKdfRequest>(data)?;
        let id = request.id;
        let hash = ecdh_kdf_hash(request.hash)?;
        let output_length = usize::from(request.output_length);
        if output_length == 0 || !secure_response_data_fits(output_length) {
            return Err(DeviceError::WrongLength);
        }
        let peer_public = request.peer_public;
        let prefix = request.prefix;
        let shared_info = request.shared_info;

        let object = self.asymmetric_object(authorization, id)?;
        let shared_secret = raw_ecdh_secret(object, peer_public)?;
        let mut prefixed = Zeroizing::new(Vec::with_capacity(
            prefix.len().saturating_add(shared_secret.len()),
        ));
        prefixed.extend_from_slice(prefix);
        prefixed.extend_from_slice(&shared_secret);
        x963_kdf(hash, &prefixed, shared_info, output_length)
            .map(|output| output.to_vec())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn session_object_command(
        &self,
        authorization: SessionAuthorization,
        objects: &mut SessionObjects,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<SessionObjectRequest>(data)?;
        match request.operation {
            SessionObjectCommand::Read => {
                return self.read_session_object(objects, request.payload);
            }
            SessionObjectCommand::VerifyCmac => {
                return self.verify_session_object(objects, request.payload);
            }
            SessionObjectCommand::DeleteObject => {
                return self.delete_session_object(objects, request.payload);
            }
            SessionObjectCommand::GenerateAsymmetricKey => {
                let request =
                    decode_request::<GenerateSessionAsymmetricKeyRequest>(request.payload)?;
                validate_session_flags(request.flags)?;
                if request.algorithm != Algorithm::EcP256 as u8 || request.flags & FLAG_DERIVE == 0
                {
                    return Err(DeviceError::InvalidData);
                }
                let key = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256))
                    .map_err(|_| DeviceError::StorageFailed)?;
                let object = SessionObject::p256_private(request.flags, key)
                    .ok_or(DeviceError::InvalidData)?;
                let public = object.public_key().ok_or(DeviceError::StorageFailed)?;
                let handle = objects.insert(object).ok_or(DeviceError::StorageFailed)?;
                let mut response = Vec::with_capacity(8 + public.len());
                response.extend_from_slice(&handle.to_be_bytes());
                response.extend_from_slice(&public);
                return Ok(response);
            }
            _ => {}
        }

        let (header, value) = match request.operation {
            SessionObjectCommand::DeriveEcdh => {
                let request = decode_request::<DeriveSessionEcdhRequest>(request.payload)?;
                let output_length = validate_session_result_header(request.header)?;
                let key = match request.source {
                    SessionSourceRequest::PersistentAsymmetric(id) => {
                        let object = self.asymmetric_object(authorization, id)?;
                        authorization.authorize_use(
                            &object.info,
                            Capability::DeriveEcdh,
                            Capability::DeriveEcdh,
                        )?;
                        signing_key(object)?
                    }
                    SessionSourceRequest::Volatile(handle) => {
                        let object = objects.get(handle).ok_or(DeviceError::ObjectNotFound)?;
                        if object.flags & FLAG_DERIVE == 0 {
                            return Err(DeviceError::InsufficientPermissions);
                        }
                        object.p256_key().ok_or(DeviceError::InvalidData)?
                    }
                    SessionSourceRequest::PersistentSymmetric(_) => {
                        return Err(DeviceError::InvalidData);
                    }
                };
                let value = derive_with_signing_key(key, request.peer_public)
                    .map_err(|_| DeviceError::InvalidData)?;
                if output_length > value.len() {
                    return Err(DeviceError::WrongLength);
                }
                let offset = value.len() - output_length;
                (request.header, Zeroizing::new(value[offset..].to_vec()))
            }
            SessionObjectCommand::ConcatenateKey => {
                let request = decode_request::<ConcatenateSessionKeysRequest>(request.payload)?;
                let output_length = validate_session_result_header(request.header)?;
                let left = session_derivation_secret(objects, request.left)?;
                let right = session_derivation_secret(objects, request.right)?;
                let available = left
                    .len()
                    .checked_add(right.len())
                    .ok_or(DeviceError::WrongLength)?;
                if output_length > available {
                    return Err(DeviceError::WrongLength);
                }
                let mut value = Zeroizing::new(Vec::with_capacity(output_length));
                value.extend(left.iter().chain(right.iter()).take(output_length).copied());
                (request.header, value)
            }
            SessionObjectCommand::ConcatenateData => {
                let request = decode_request::<ConcatenateSessionDataRequest>(request.payload)?;
                let output_length = validate_session_result_header(request.header)?;
                let base = session_derivation_secret(objects, request.base)?;
                let available = base
                    .len()
                    .checked_add(request.data.len())
                    .ok_or(DeviceError::WrongLength)?;
                if output_length > available {
                    return Err(DeviceError::WrongLength);
                }
                let mut value = Zeroizing::new(Vec::with_capacity(output_length));
                value.extend(base.iter().chain(request.data).take(output_length).copied());
                (request.header, value)
            }
            SessionObjectCommand::Extract => {
                let request = decode_request::<ExtractSessionObjectRequest>(request.payload)?;
                let output_length = validate_session_result_header(request.header)?;
                let base = session_derivation_secret(objects, request.base)?;
                let offset = usize::from(request.offset);
                if offset >= base.len() * 8 {
                    return Err(DeviceError::InvalidData);
                }
                if output_length > base.len() {
                    return Err(DeviceError::WrongLength);
                }
                let mut value = Zeroizing::new(Vec::with_capacity(output_length));
                for index in 0..output_length {
                    let bit = (offset + index * 8) % (base.len() * 8);
                    let byte_index = bit / 8;
                    let shift = bit % 8;
                    value.push(if shift == 0 {
                        base[byte_index]
                    } else {
                        (base[byte_index] << shift)
                            | (base[(byte_index + 1) % base.len()] >> (8 - shift))
                    });
                }
                (request.header, value)
            }
            SessionObjectCommand::Sha256 => {
                let request = decode_request::<Sha256SessionObjectRequest>(request.payload)?;
                let output_length = validate_session_result_header(request.header)?;
                if output_length > 32 {
                    return Err(DeviceError::WrongLength);
                }
                let base = session_derivation_secret(objects, request.base)?;
                let digest = HashAlgorithm::Sha256.digest(&base);
                (
                    request.header,
                    Zeroizing::new(digest[..output_length].to_vec()),
                )
            }
            SessionObjectCommand::CounterKdf => {
                let request = decode_request::<CounterKdfSessionObjectRequest>(request.payload)?;
                let output_length = validate_session_result_header(request.header)?;
                let key = match request.source {
                    SessionSourceRequest::PersistentSymmetric(id) => {
                        let object = self.symmetric_object(authorization, id)?;
                        authorization.authorize_use(
                            &object.info,
                            Capability::EncryptEcb,
                            Capability::EncryptEcb,
                        )?;
                        Zeroizing::new(object_secret(object)?.to_vec())
                    }
                    SessionSourceRequest::Volatile(handle) => {
                        session_derivation_secret(objects, handle)?
                    }
                    SessionSourceRequest::PersistentAsymmetric(_) => {
                        return Err(DeviceError::InvalidData);
                    }
                };
                let value = cmac_counter_kdf(&key, &request.fields, output_length)
                    .map_err(|_| DeviceError::InvalidData)?;
                (request.header, value)
            }
            _ => return Err(DeviceError::InvalidData),
        };
        let object = SessionObject::secret(header.kind, header.flags, value)
            .ok_or(DeviceError::InvalidData)?;
        let handle = objects.insert(object).ok_or(DeviceError::StorageFailed)?;
        Ok(handle.to_be_bytes().to_vec())
    }

    fn read_session_object(&self, objects: &SessionObjects, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<ReadSessionObjectRequest>(data)?;
        let object = objects
            .get(request.handle)
            .ok_or(DeviceError::ObjectNotFound)?;
        if object.flags & FLAG_READABLE == 0 {
            return Err(DeviceError::InsufficientPermissions);
        }
        object
            .secret_value()
            .map(Vec::from)
            .ok_or(DeviceError::InvalidData)
    }

    fn verify_session_object(&self, objects: &SessionObjects, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<VerifySessionCmacRequest>(data)?;
        let object = objects
            .get(request.handle)
            .ok_or(DeviceError::ObjectNotFound)?;
        if object.kind != SessionObjectKind::Aes || object.flags & FLAG_VERIFY == 0 {
            return Err(DeviceError::InsufficientPermissions);
        }
        let key = object.secret_value().ok_or(DeviceError::InvalidData)?;
        if !(1..=AES_BLOCK_SIZE).contains(&request.signature.len()) {
            return Err(DeviceError::WrongLength);
        }
        let expected = aes_cmac(key, request.message).map_err(|_| DeviceError::InvalidData)?;
        Ok(vec![u8::from(bool::from(
            expected[..request.signature.len()].ct_eq(request.signature),
        ))])
    }

    fn delete_session_object(&self, objects: &mut SessionObjects, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<DeleteSessionObjectRequest>(data)?;
        objects
            .remove(request.handle)
            .ok_or(DeviceError::ObjectNotFound)?;
        Ok(Vec::new())
    }

    fn decrypt_pkcs1(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<DecryptPkcs1Request>(data)?;
        if request.ciphertext.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let object = self.asymmetric_object(authorization, request.id)?;
        rsa_key(object)?
            .decrypt_rsa_pkcs1v15(request.ciphertext)
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn decrypt_oaep(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<DecryptOaepRequest>(data)?;
        let object = self.asymmetric_object(authorization, request.id)?;
        let modulus_length = rsa_modulus_length(object)?;
        let digest_length = request
            .ciphertext_and_label
            .len()
            .checked_sub(modulus_length)
            .ok_or(DeviceError::WrongLength)?;
        if !matches!(digest_length, 20 | 32 | 48 | 64) {
            return Err(DeviceError::WrongLength);
        }
        let mgf_hash = rsa_mgf_hash(request.mgf_hash)?;
        rsa_key(object)?
            .decrypt_rsa_oaep_digest(
                &request.ciphertext_and_label[..modulus_length],
                &request.ciphertext_and_label[modulus_length..],
                mgf_hash,
            )
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn asymmetric_object(
        &self,
        authorization: SessionAuthorization,
        id: u16,
    ) -> Result<&ObjectRecord> {
        let object = self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::AsymmetricKey,
                id,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.require_visible(&object.info)?;
        self.require_algorithm_enabled(object.info.algorithm)?;
        Ok(object)
    }

    fn put_hmac_key(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
        generate: bool,
    ) -> Result<Vec<u8>> {
        let (header, supplied) = if generate {
            let request = decode_request::<GenerateHmacKeyRequest>(data)?;
            (request.header, request.material)
        } else {
            let request = decode_request::<PutHmacKeyRequest>(data)?;
            (request.header, request.material)
        };
        if generate && !supplied.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let algorithm = header.algorithm;
        self.require_algorithm_enabled(algorithm)?;
        let generated_length = hmac_length(algorithm)?;
        let secret = if generate {
            let mut value = vec![0; generated_length];
            getrandom::fill(&mut value).map_err(|_| DeviceError::StorageFailed)?;
            value
        } else {
            let value = supplied.to_vec();
            if value.is_empty() || value.len() > 128 {
                return Err(DeviceError::WrongLength);
            }
            value
        };
        let id = self.resolve_id(ObjectType::HmacKey, header.requested_id)?;
        let capability = if generate {
            Capability::GenerateHmacKey
        } else {
            Capability::PutMacKey
        };
        let info = ObjectInfo {
            capabilities: header.capabilities,
            id,
            length: Algorithm::from_byte(algorithm)
                .and_then(Algorithm::hmac_object_length)
                .ok_or(DeviceError::InvalidData)? as u16,
            domains: header.domains,
            object_type: ObjectType::HmacKey,
            algorithm,
            sequence: 0,
            origin: if generate { 1 } else { 2 },
            label: trim_label(header.label),
            delegated_capabilities: CapabilitySet::NONE,
        };
        authorization.authorize_create(&info, capability)?;
        let record = ObjectRecord {
            info,
            material: ObjectMaterial::Secret(secret),
        };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn put_symmetric_key(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
        generate: bool,
    ) -> Result<Vec<u8>> {
        let (header, supplied) = if generate {
            let request = decode_request::<GenerateSymmetricKeyRequest>(data)?;
            (request.header, request.material)
        } else {
            let request = decode_request::<PutSymmetricKeyRequest>(data)?;
            (request.header, request.material)
        };
        if generate && !supplied.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let algorithm = Algorithm::from_byte(header.algorithm).ok_or(DeviceError::InvalidData)?;
        self.require_algorithm_enabled(algorithm as u8)?;
        let key_length = algorithm
            .aes_key_length()
            .filter(|_| {
                matches!(
                    algorithm,
                    Algorithm::Aes128 | Algorithm::Aes192 | Algorithm::Aes256
                )
            })
            .ok_or(DeviceError::InvalidData)?;
        let secret = if generate {
            let mut secret = vec![0; key_length];
            getrandom::fill(&mut secret).map_err(|_| DeviceError::StorageFailed)?;
            secret
        } else {
            if supplied.len() != key_length {
                return Err(DeviceError::WrongLength);
            }
            supplied.to_vec()
        };
        let id = self.resolve_id(ObjectType::SymmetricKey, header.requested_id)?;
        let capability = if generate {
            Capability::GenerateSymmetricKey
        } else {
            Capability::PutSymmetricKey
        };
        let info = ObjectInfo {
            capabilities: header.capabilities,
            id,
            length: key_length as u16,
            domains: header.domains,
            object_type: ObjectType::SymmetricKey,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: if generate { 1 } else { 2 },
            label: trim_label(header.label),
            delegated_capabilities: CapabilitySet::NONE,
        };
        authorization.authorize_create(&info, capability)?;
        let record = ObjectRecord {
            info,
            material: ObjectMaterial::Secret(secret),
        };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn put_wrap_key(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
        generate: bool,
    ) -> Result<Vec<u8>> {
        let request = if generate {
            decode_request::<GenerateWrapKeyRequest>(data)?.0
        } else {
            decode_request::<PutWrapKeyRequest>(data)?.0
        };
        if generate && !request.material.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let header = request.header;
        let algorithm = Algorithm::from_byte(header.algorithm).ok_or(DeviceError::InvalidData)?;
        self.require_algorithm_enabled(algorithm as u8)?;
        let key_length = match algorithm {
            Algorithm::Aes128CcmWrap | Algorithm::Aes192CcmWrap | Algorithm::Aes256CcmWrap => {
                algorithm.aes_key_length().unwrap()
            }
            Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => {
                algorithm.asymmetric_key_length().unwrap()
            }
            _ => return Err(DeviceError::InvalidData),
        };
        let material = if algorithm.is_rsa_key() {
            asymmetric_key_material(algorithm, generate, request.material)?
        } else if generate {
            let mut secret = vec![0; key_length];
            getrandom::fill(&mut secret).map_err(|_| DeviceError::StorageFailed)?;
            ObjectMaterial::Secret(secret)
        } else {
            if request.material.len() != key_length {
                return Err(DeviceError::WrongLength);
            }
            ObjectMaterial::Secret(request.material.to_vec())
        };
        let id = self.resolve_id(ObjectType::WrapKey, header.requested_id)?;
        let capability = if generate {
            Capability::GenerateWrapKey
        } else {
            Capability::PutWrapKey
        };
        let object_length = if algorithm.is_rsa_key() {
            algorithm
                .asymmetric_object_length()
                .and_then(|length| length.checked_add(8))
                .ok_or(DeviceError::InvalidData)?
        } else {
            key_length + 8
        };
        let info = ObjectInfo {
            capabilities: header.capabilities,
            id,
            length: object_length as u16,
            domains: header.domains,
            object_type: ObjectType::WrapKey,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: if generate { 1 } else { 2 },
            label: trim_label(header.label),
            delegated_capabilities: request.delegated_capabilities,
        };
        authorization.authorize_create(&info, capability)?;
        let record = ObjectRecord { info, material };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn put_public_wrap_key(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<PutPublicWrapKeyRequest>(data)?.0;
        let header = request.header;
        let algorithm = Algorithm::from_byte(header.algorithm).ok_or(DeviceError::InvalidData)?;
        self.require_algorithm_enabled(algorithm as u8)?;
        if !algorithm.is_rsa_key() {
            return Err(DeviceError::InvalidData);
        }
        let key_length = algorithm.asymmetric_key_length().unwrap();
        if request.material.len() != key_length {
            return Err(DeviceError::WrongLength);
        }
        let id = self.resolve_id(ObjectType::PublicWrapKey, header.requested_id)?;
        let info = ObjectInfo {
            capabilities: header.capabilities,
            id,
            length: (key_length + 8) as u16,
            domains: header.domains,
            object_type: ObjectType::PublicWrapKey,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: 2,
            label: trim_label(header.label),
            delegated_capabilities: request.delegated_capabilities,
        };
        authorization.authorize_create(&info, Capability::PutPublicWrapKey)?;
        let record = ObjectRecord {
            info,
            material: ObjectMaterial::Public(request.material.to_vec()),
        };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn wrap_data(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<WrapDataRequest>(data)?;
        let object = self.ccm_wrap_key(authorization, request.id)?;
        let mut nonce = [0; AES_CCM_NONCE_SIZE];
        getrandom::fill(&mut nonce).map_err(|_| DeviceError::StorageFailed)?;
        let encrypted = encrypt_aes_ccm(object_secret(object)?, &nonce, request.plaintext)
            .map_err(|_| DeviceError::InvalidData)?;
        let mut output = Vec::with_capacity(1 + AES_CCM_NONCE_SIZE + encrypted.len());
        output.push(1);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&encrypted);
        Ok(output)
    }

    fn unwrap_data(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        const OVERHEAD: usize = 1 + AES_CCM_NONCE_SIZE + AES_CCM_TAG_SIZE;
        let request = decode_request::<UnwrapDataRequest>(data)?;
        if request.wrapped.len() < OVERHEAD || request.wrapped[0] != 1 {
            return Err(DeviceError::WrongLength);
        }
        let object = self.ccm_wrap_key(authorization, request.id)?;
        decrypt_aes_ccm(
            object_secret(object)?,
            &request.wrapped[1..1 + AES_CCM_NONCE_SIZE],
            &request.wrapped[1 + AES_CCM_NONCE_SIZE..],
        )
        .map_err(|_| DeviceError::InvalidData)
    }

    fn export_wrapped(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<ExportWrappedRequest>(data)?;
        if request.format.is_some_and(|format| format > 1) {
            return Err(DeviceError::WrongLength);
        }
        let wrap_id = request.wrap_id;
        let target_key = request.target;
        let wrap_key = self.ccm_wrap_key(authorization, wrap_id)?;
        let target = self
            .objects
            .get(&target_key)
            .ok_or(DeviceError::ObjectNotFound)?;
        let plaintext = encode_wrapped_object(target)?;
        let mut nonce = [0; AES_CCM_NONCE_SIZE];
        getrandom::fill(&mut nonce).map_err(|_| DeviceError::StorageFailed)?;
        let encrypted = encrypt_aes_ccm(object_secret(wrap_key)?, &nonce, &plaintext)
            .map_err(|_| DeviceError::InvalidData)?;
        Ok([&[1], nonce.as_slice(), encrypted.as_slice()].concat())
    }

    fn import_wrapped(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<ImportWrappedRequest>(data)?;
        if request.format != 1 || request.ciphertext.len() < AES_CCM_TAG_SIZE {
            return Err(DeviceError::WrongLength);
        }
        let wrap_id = request.wrap_id;
        let mut record = {
            let wrap_key = self.ccm_wrap_key(authorization, wrap_id)?;
            let plaintext =
                decrypt_aes_ccm(object_secret(wrap_key)?, request.nonce, request.ciphertext)
                    .map_err(|_| DeviceError::InvalidData)?;
            let record = decode_wrapped_object(&plaintext)?;
            authorization.authorize_wrapped_creation(&record.info, wrap_key)?;
            record
        };
        record.info.id = self.resolve_id(record.info.object_type, record.info.id)?;
        record.info.origin |= 0x10;
        record.validate()?;
        let response = [
            &[record.info.object_type as u8],
            record.info.id.to_be_bytes().as_slice(),
        ]
        .concat();
        self.write_object(record)?;
        Ok(response)
    }

    fn export_rsa_wrapped(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
        key_material_only: bool,
    ) -> Result<Vec<u8>> {
        let request = if key_material_only {
            decode_request::<GetRsaWrappedKeyRequest>(data)?.0
        } else {
            decode_request::<ExportRsaWrappedRequest>(data)?.0
        };
        let wrap_id = request.wrap_id;
        let target_key = request.target;
        let wrap_key = self.rsa_public_wrap_key(authorization, wrap_id)?;
        let target = self
            .objects
            .get(&target_key)
            .ok_or(DeviceError::ObjectNotFound)?;
        let direct_pkcs1 =
            request.aes_algorithm == 0 && request.oaep_hash == 0 && request.mgf_hash == 0;
        if direct_pkcs1 {
            if !FirmwareProfile::compiled().direct_rsa_wrap() {
                return Err(DeviceError::InvalidData);
            }
            if self.options.fips_mode != OPTION_OFF {
                return Err(DeviceError::InvalidData);
            }
            if !request.label_hash.is_empty() {
                return Err(DeviceError::WrongLength);
            }
            if !key_material_only || target_key.object_type != ObjectType::SymmetricKey {
                return Err(DeviceError::InvalidData);
            }
            let ObjectMaterial::Secret(plaintext) = &target.material else {
                return Err(DeviceError::InvalidData);
            };
            let public = match &wrap_key.material {
                ObjectMaterial::Public(modulus) => SoftwarePublicKey::Rsa {
                    modulus: modulus.clone(),
                    exponent: vec![1, 0, 1],
                },
                _ => return Err(DeviceError::InvalidData),
            };
            return public
                .encrypt_rsa_pkcs1v15(plaintext)
                .map_err(|_| DeviceError::InvalidData);
        }

        let label_length = rsa_oaep_hash(request.oaep_hash)?.output_length();
        if request.label_hash.len() != label_length {
            return Err(DeviceError::WrongLength);
        }
        if key_material_only
            && !matches!(
                target_key.object_type,
                ObjectType::AsymmetricKey | ObjectType::SymmetricKey
            )
        {
            return Err(DeviceError::InvalidData);
        }
        let aes_length = rsa_wrap_aes_length(request.aes_algorithm)?;
        let mgf_hash = rsa_mgf_hash(request.mgf_hash)?;
        let plaintext = if key_material_only {
            match target_key.object_type {
                ObjectType::AsymmetricKey => asymmetric_pkcs8(target)?,
                ObjectType::SymmetricKey => object_secret(target)?.to_vec(),
                _ => return Err(DeviceError::InvalidData),
            }
        } else {
            encode_wrapped_object(target)?
        };
        let public = match &wrap_key.material {
            ObjectMaterial::Public(modulus) => SoftwarePublicKey::Rsa {
                modulus: modulus.clone(),
                exponent: vec![1, 0, 1],
            },
            _ => return Err(DeviceError::InvalidData),
        };
        rsa_aes_wrap(
            &public,
            aes_length,
            &plaintext,
            request.label_hash,
            mgf_hash,
        )
    }

    fn import_rsa_wrapped(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<ImportRsaWrappedRequest>(data)?;
        let label_length = rsa_oaep_hash(request.oaep_hash)?.output_length();
        let wrap_id = request.wrap_id;
        let mgf_hash = rsa_mgf_hash(request.mgf_hash)?;
        let mut record = {
            let wrap_key = self.rsa_private_wrap_key(authorization, wrap_id)?;
            let modulus_length = rsa_modulus_length(wrap_key)?;
            if request.wrapped_and_label.len() < modulus_length + 16 + label_length {
                return Err(DeviceError::WrongLength);
            }
            let wrapped_end = request.wrapped_and_label.len() - label_length;
            let plaintext = rsa_aes_unwrap(
                signing_key(wrap_key)?,
                &request.wrapped_and_label[..wrapped_end],
                modulus_length,
                &request.wrapped_and_label[wrapped_end..],
                mgf_hash,
            )?;
            let record = decode_wrapped_object(&plaintext)?;
            authorization.authorize_wrapped_creation(&record.info, wrap_key)?;
            record
        };
        record.info.id = self.resolve_id(record.info.object_type, record.info.id)?;
        record.info.origin |= 0x10;
        record.validate()?;
        let response = [
            &[record.info.object_type as u8],
            record.info.id.to_be_bytes().as_slice(),
        ]
        .concat();
        self.write_object(record)?;
        Ok(response)
    }

    fn put_rsa_wrapped_key(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<PutRsaWrappedKeyRequest>(data)?;
        let object_type = request.object_type;
        if !matches!(
            object_type,
            ObjectType::AsymmetricKey | ObjectType::SymmetricKey
        ) {
            return Err(DeviceError::InvalidData);
        }
        let algorithm = Algorithm::from_byte(request.algorithm).ok_or(DeviceError::InvalidData)?;
        self.require_algorithm_enabled(algorithm as u8)?;
        let wrap_id = request.wrap_id;
        let direct_pkcs1 = request.oaep_hash == 0 && request.mgf_hash == 0;
        let (material, logical_length) = {
            let wrap_key = self.rsa_private_wrap_key(authorization, wrap_id)?;
            let modulus_length = rsa_modulus_length(wrap_key)?;
            let plaintext = if direct_pkcs1 {
                if !FirmwareProfile::compiled().direct_rsa_wrap() {
                    return Err(DeviceError::InvalidData);
                }
                if self.options.fips_mode != OPTION_OFF {
                    return Err(DeviceError::InvalidData);
                }
                if object_type != ObjectType::SymmetricKey {
                    return Err(DeviceError::InvalidData);
                }
                if request.wrapped_and_label.len() != modulus_length {
                    return Err(DeviceError::WrongLength);
                }
                signing_key(wrap_key)?
                    .decrypt_rsa_pkcs1v15(request.wrapped_and_label)
                    .map_err(|_| DeviceError::InvalidData)?
                    .to_vec()
            } else {
                let label_digest_length = rsa_oaep_hash(request.oaep_hash)?.output_length();
                let mgf_hash = rsa_mgf_hash(request.mgf_hash)?;
                if request.wrapped_and_label.len() <= modulus_length + label_digest_length {
                    return Err(DeviceError::WrongLength);
                }
                let wrapped_end = request.wrapped_and_label.len() - label_digest_length;
                rsa_aes_unwrap(
                    signing_key(wrap_key)?,
                    &request.wrapped_and_label[..wrapped_end],
                    modulus_length,
                    &request.wrapped_and_label[wrapped_end..],
                    mgf_hash,
                )?
            };
            import_rsa_wrapped_key_material(object_type, algorithm, &plaintext)?
        };
        let id = self.resolve_id(object_type, request.requested_id)?;
        let info = ObjectInfo {
            capabilities: request.capabilities,
            id,
            length: match object_type {
                ObjectType::AsymmetricKey => algorithm
                    .asymmetric_object_length()
                    .ok_or(DeviceError::InvalidData)?,
                ObjectType::SymmetricKey => logical_length,
                _ => return Err(DeviceError::InvalidData),
            }
            .try_into()
            .map_err(|_| DeviceError::WrongLength)?,
            domains: request.domains,
            object_type,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: 0x12,
            label: trim_label(request.label),
            delegated_capabilities: CapabilitySet::NONE,
        };
        {
            let wrap_key = self.rsa_private_wrap_key(authorization, wrap_id)?;
            authorization.authorize_wrapped_creation(&info, wrap_key)?;
        }
        let record = ObjectRecord { info, material };
        record.validate()?;
        let response = [
            &[object_type as u8],
            record.info.id.to_be_bytes().as_slice(),
        ]
        .concat();
        self.write_object(record)?;
        Ok(response)
    }

    fn rsa_public_wrap_key(
        &self,
        authorization: SessionAuthorization,
        id: u16,
    ) -> Result<&ObjectRecord> {
        let object = self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::PublicWrapKey,
                id,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.require_visible(&object.info)?;
        self.require_algorithm_enabled(object.info.algorithm)?;
        Ok(object)
    }

    fn rsa_private_wrap_key(
        &self,
        authorization: SessionAuthorization,
        id: u16,
    ) -> Result<&ObjectRecord> {
        let object = self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::WrapKey,
                id,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.require_visible(&object.info)?;
        self.require_algorithm_enabled(object.info.algorithm)?;
        if !Algorithm::from_byte(object.info.algorithm).is_some_and(Algorithm::is_rsa_key) {
            return Err(DeviceError::InvalidData);
        }
        Ok(object)
    }

    fn ccm_wrap_key(&self, authorization: SessionAuthorization, id: u16) -> Result<&ObjectRecord> {
        let object = self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::WrapKey,
                id,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.require_visible(&object.info)?;
        self.require_algorithm_enabled(object.info.algorithm)?;
        if !matches!(
            Algorithm::from_byte(object.info.algorithm),
            Some(Algorithm::Aes128CcmWrap | Algorithm::Aes192CcmWrap | Algorithm::Aes256CcmWrap)
        ) {
            return Err(DeviceError::InvalidData);
        }
        Ok(object)
    }

    fn crypt_aes_ecb(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
        encrypt: bool,
    ) -> Result<Vec<u8>> {
        let (id, input) = if encrypt {
            let request = decode_request::<EncryptEcbRequest>(data)?;
            (request.id, request.plaintext)
        } else {
            let request = decode_request::<DecryptEcbRequest>(data)?;
            (request.id, request.ciphertext)
        };
        if input.len() < AES_BLOCK_SIZE || !input.len().is_multiple_of(AES_BLOCK_SIZE) {
            return Err(DeviceError::WrongLength);
        }
        let object = self.symmetric_object(authorization, id)?;
        let key = object_secret(object)?;
        let result = if encrypt {
            encrypt_aes_ecb(key, input)
        } else {
            decrypt_aes_ecb(key, input)
        };
        result.map_err(|_| DeviceError::InvalidData)
    }

    fn crypt_aes_cbc(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
        encrypt: bool,
    ) -> Result<Vec<u8>> {
        let request = if encrypt {
            decode_request::<EncryptCbcRequest>(data)?.0
        } else {
            decode_request::<DecryptCbcRequest>(data)?.0
        };
        if request.input.len() < AES_BLOCK_SIZE
            || !request.input.len().is_multiple_of(AES_BLOCK_SIZE)
        {
            return Err(DeviceError::WrongLength);
        }
        let object = self.symmetric_object(authorization, request.id)?;
        let key = object_secret(object)?;
        let iv = request.iv;
        let input = request.input;
        let result = if encrypt {
            encrypt_aes_cbc(key, iv, input)
        } else {
            decrypt_aes_cbc(key, iv, input)
        };
        result.map_err(|_| DeviceError::InvalidData)
    }

    fn symmetric_object(
        &self,
        authorization: SessionAuthorization,
        id: u16,
    ) -> Result<&ObjectRecord> {
        let object = self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::SymmetricKey,
                id,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.require_visible(&object.info)?;
        self.require_algorithm_enabled(object.info.algorithm)?;
        if !matches!(
            Algorithm::from_byte(object.info.algorithm),
            Some(Algorithm::Aes128 | Algorithm::Aes192 | Algorithm::Aes256)
        ) {
            return Err(DeviceError::InvalidData);
        }
        Ok(object)
    }

    fn put_otp_aead_key(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
        generate: bool,
    ) -> Result<Vec<u8>> {
        let request = if generate {
            decode_request::<GenerateOtpAeadKeyRequest>(data)?.0
        } else {
            decode_request::<PutOtpAeadKeyRequest>(data)?.0
        };
        if generate && !request.material.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        let header = request.header;
        let algorithm = Algorithm::from_byte(header.algorithm).ok_or(DeviceError::InvalidData)?;
        self.require_algorithm_enabled(algorithm as u8)?;
        let key_length = match algorithm {
            Algorithm::Aes128YubicoOtp
            | Algorithm::Aes192YubicoOtp
            | Algorithm::Aes256YubicoOtp => algorithm.aes_key_length().unwrap(),
            _ => return Err(DeviceError::InvalidData),
        };
        let key = if generate {
            let mut key = vec![0; key_length];
            getrandom::fill(&mut key).map_err(|_| DeviceError::StorageFailed)?;
            key
        } else {
            if request.material.len() != key_length {
                return Err(DeviceError::WrongLength);
            }
            request.material.to_vec()
        };
        let id = self.resolve_id(ObjectType::OtpAeadKey, header.requested_id)?;
        let capability = if generate {
            Capability::GenerateOtpAeadKey
        } else {
            Capability::PutOtpAeadKey
        };
        let info = ObjectInfo {
            capabilities: header.capabilities,
            id,
            length: (key_length + 4) as u16,
            domains: header.domains,
            object_type: ObjectType::OtpAeadKey,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: if generate { 1 } else { 2 },
            label: trim_label(header.label),
            delegated_capabilities: CapabilitySet::NONE,
        };
        authorization.authorize_create(&info, capability)?;
        let record = ObjectRecord {
            info,
            material: ObjectMaterial::OtpAeadKey {
                nonce_id: *request.nonce_id,
                key,
            },
        };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn create_otp_aead(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<CreateOtpAeadRequest>(data)?;
        let object = self.otp_aead_key(authorization, request.id)?;
        otp_aead_encrypt(object, request.credential)
    }

    fn randomize_otp_aead(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<RandomizeOtpAeadRequest>(data)?;
        let object = self.otp_aead_key(authorization, request.id)?;
        let mut credential = [0; 22];
        getrandom::fill(&mut credential).map_err(|_| DeviceError::StorageFailed)?;
        otp_aead_encrypt(object, &credential)
    }

    fn decrypt_otp(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<DecryptOtpRequest>(data)?;
        let object = self.otp_aead_key(authorization, request.id)?;
        let credential = otp_aead_decrypt(object, request.aead)?;
        let token = decrypt_aes_ecb(&credential[..16], request.otp)
            .map_err(|_| DeviceError::InvalidData)?;
        if token[..6] != credential[16..22] || yubico_crc16(&token) != 0xf0b8 {
            return Err(DeviceError::InvalidOtp);
        }
        Ok([&token[6..8], &token[11..12], &token[10..11], &token[8..10]].concat())
    }

    fn rewrap_otp_aead(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<RewrapOtpAeadRequest>(data)?;
        let from = self.otp_aead_key(authorization, request.from_id)?;
        let to = self.otp_aead_key(authorization, request.to_id)?;
        otp_aead_encrypt(to, &otp_aead_decrypt(from, request.aead)?)
    }

    fn otp_aead_key(&self, authorization: SessionAuthorization, id: u16) -> Result<&ObjectRecord> {
        let object = self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::OtpAeadKey,
                id,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.require_visible(&object.info)?;
        self.require_algorithm_enabled(object.info.algorithm)?;
        Ok(object)
    }

    fn put_template(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let request = decode_request::<PutTemplateRequest>(data)?;
        let header = request.header;
        if request.material.is_empty() {
            return Err(DeviceError::WrongLength);
        }
        if header.algorithm != Algorithm::TemplateSsh as u8 {
            return Err(DeviceError::InvalidData);
        }
        self.require_algorithm_enabled(header.algorithm)?;
        let material = request.material.to_vec();
        let id = self.resolve_id(ObjectType::Template, header.requested_id)?;
        let info = ObjectInfo {
            capabilities: header.capabilities,
            id,
            length: material
                .len()
                .try_into()
                .map_err(|_| DeviceError::WrongLength)?,
            domains: header.domains,
            object_type: ObjectType::Template,
            algorithm: header.algorithm,
            sequence: 0,
            origin: 2,
            label: trim_label(header.label),
            delegated_capabilities: CapabilitySet::NONE,
        };
        authorization.authorize_create(&info, Capability::PutTemplate)?;
        let record = ObjectRecord {
            info,
            material: ObjectMaterial::Opaque(material),
        };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn get_template(&self, data: &[u8]) -> Result<Vec<u8>> {
        let id = decode_request::<GetTemplateRequest>(data)?.id;
        let object = self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::Template,
                id,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        match &object.material {
            ObjectMaterial::Opaque(template) => Ok(template.clone()),
            _ => Err(DeviceError::InvalidData),
        }
    }

    fn sign_hmac(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<SignHmacRequest>(data)?;
        let object = self.hmac_object(authorization, request.id)?;
        calculate_hmac(object, request.message)
    }

    fn verify_hmac(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<VerifyHmacRequest>(data)?;
        let object = self.hmac_object(authorization, request.id)?;
        let signature_length = hmac_length(object.info.algorithm)?;
        if request.signature_and_message.len() < signature_length {
            return Err(DeviceError::WrongLength);
        }
        let (signature, message) = request.signature_and_message.split_at(signature_length);
        let expected = calculate_hmac(object, message)?;
        Ok(vec![u8::from(bool::from(
            expected.as_slice().ct_eq(signature),
        ))])
    }

    fn hmac_object(&self, authorization: SessionAuthorization, id: u16) -> Result<&ObjectRecord> {
        let object = self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::HmacKey,
                id,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.require_visible(&object.info)?;
        self.require_algorithm_enabled(object.info.algorithm)?;
        Ok(object)
    }

    fn change_authentication_key(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let request = decode_request::<ChangeAuthenticationKeyRequest>(data)?;
        let id = request.id;
        let algorithm = request.algorithm;
        self.require_algorithm_enabled(algorithm)?;
        let key_length = authentication_key_length(algorithm)?;
        if request.material.len() != key_length {
            return Err(DeviceError::WrongLength);
        }
        let key = ObjectKey {
            object_type: ObjectType::AuthenticationKey,
            id,
        };
        let material = parse_authentication_key_material(algorithm, request.material)?;
        let mut updated = self
            .objects
            .get(&key)
            .cloned()
            .ok_or(DeviceError::ObjectNotFound)?;
        updated.info.algorithm = algorithm;
        updated.info.length = (key_length + 8) as u16;
        updated.material = ObjectMaterial::Authentication(material);
        self.write_object(updated)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn resolve_id(&self, object_type: ObjectType, requested: u16) -> Result<u16> {
        if requested == u16::MAX {
            return Err(DeviceError::InvalidId);
        }
        if requested != 0 {
            if self.objects.contains_key(&ObjectKey {
                object_type,
                id: requested,
            }) {
                return Err(DeviceError::ObjectExists);
            }
            return Ok(requested);
        }
        self.random_available_id_with(|| {
            let mut encoded = [0; 2];
            getrandom::fill(&mut encoded).map_err(|_| DeviceError::StorageFailed)?;
            Ok(u16::from_be_bytes(encoded))
        })
    }

    fn random_available_id_with<F>(&self, mut next_id: F) -> Result<u16>
    where
        F: FnMut() -> Result<u16>,
    {
        loop {
            let id = next_id()?;
            if id != 0 && id != u16::MAX && !self.objects.keys().any(|key| key.id == id) {
                return Ok(id);
            }
        }
    }

    fn next_generation(&self, id: u16) -> u64 {
        self.sequence_history
            .generation(id)
            .map_or(0, |generation| generation.wrapping_add(1))
    }

    fn write_object(&mut self, mut record: ObjectRecord) -> Result<()> {
        record.promote_private_material()?;
        record.validate()?;
        let key = record.info.key();
        let generation = self.next_generation(key.id);
        record.info.sequence = generation as u8;
        self.sequence_history.record(key.id, generation);
        self.objects.insert(key, record);
        Ok(())
    }

    fn install_factory_authentication_key(&mut self) {
        let static_keys = yubico_password_kdf(b"password");
        let record = ObjectRecord {
            info: ObjectInfo {
                capabilities: CapabilitySet::ALL,
                id: 1,
                length: 40,
                domains: u16::MAX,
                object_type: ObjectType::AuthenticationKey,
                algorithm: DEFAULT_AUTHENTICATION_ALGORITHM,
                sequence: 0,
                origin: 2,
                label: b"DEFAULT AUTHKEY CHANGE THIS".to_vec(),
                delegated_capabilities: CapabilitySet::ALL,
            },
            material: ObjectMaterial::Authentication(AuthenticationKeyMaterial::Symmetric(
                static_keys.to_vec(),
            )),
        };
        let key = record.info.key();
        self.sequence_history.record(key.id, 0);
        self.objects.insert(key, record);
    }
}

fn version_two_object_length(object: &ObjectRecord) -> Result<usize> {
    let algorithm = Algorithm::from_byte(object.info.algorithm);
    match object.info.object_type {
        ObjectType::AsymmetricKey => match algorithm {
            // Version 2 predated the physical-HSM measurement for Ed25519.
            Some(Algorithm::Ed25519) => Ok(64),
            Some(algorithm) => algorithm
                .asymmetric_object_length()
                .ok_or(DeviceError::InvalidData),
            None => Err(DeviceError::InvalidData),
        },
        ObjectType::WrapKey if algorithm.is_some_and(Algorithm::is_rsa_key) => algorithm
            .and_then(Algorithm::asymmetric_object_length)
            .ok_or(DeviceError::InvalidData),
        _ => Ok(object.material.len()),
    }
}

fn authentication_key_length(algorithm: u8) -> Result<usize> {
    match algorithm {
        AUTHENTICATION_ALGORITHM_AES128_YUBICO => Ok(32),
        AUTHENTICATION_ALGORITHM_EC_P256 => Ok(64),
        _ => Err(DeviceError::InvalidData),
    }
}

fn random_device_static_private() -> Result<[u8; 32]> {
    random_secret_key()?
        .serialized()
        .map_err(|_| DeviceError::StorageFailed)?
        .as_slice()
        .try_into()
        .map_err(|_| DeviceError::StorageFailed)
}

fn parse_authentication_key_material(
    algorithm: u8,
    key: &[u8],
) -> Result<AuthenticationKeyMaterial> {
    match algorithm {
        AUTHENTICATION_ALGORITHM_AES128_YUBICO if key.len() == 32 => {
            Ok(AuthenticationKeyMaterial::Symmetric(key.to_vec()))
        }
        AUTHENTICATION_ALGORITHM_EC_P256 if key.len() == 64 => {
            let encoded = [vec![0x04], key.to_vec()].concat();
            SoftwarePublicKey::Ec {
                curve: EcCurve::P256,
                uncompressed: encoded,
            }
            .validate()
            .map_err(|_| DeviceError::InvalidData)?;
            Ok(AuthenticationKeyMaterial::Asymmetric(key.to_vec()))
        }
        AUTHENTICATION_ALGORITHM_AES128_YUBICO | AUTHENTICATION_ALGORITHM_EC_P256 => {
            Err(DeviceError::WrongLength)
        }
        _ => Err(DeviceError::InvalidData),
    }
}

fn asymmetric_key_algorithm(algorithm: u8) -> Result<(SignatureScheme, usize)> {
    match algorithm {
        47 => Ok((SignatureScheme::EcdsaP224Sha224, 28)),
        12 => Ok((SignatureScheme::EcdsaP256Sha256, 32)),
        13 => Ok((SignatureScheme::EcdsaP384Sha384, 48)),
        14 => Ok((SignatureScheme::EcdsaP521Sha512, 66)),
        15 => Ok((SignatureScheme::EcdsaSecp256k1Sha256, 32)),
        16 => Ok((SignatureScheme::EcdsaBrainpoolP256Sha256, 32)),
        17 => Ok((SignatureScheme::EcdsaBrainpoolP384Sha384, 48)),
        18 => Ok((SignatureScheme::EcdsaBrainpoolP512Sha512, 64)),
        46 => Ok((SignatureScheme::Ed25519, 32)),
        60 => Ok((SignatureScheme::Ed448, 57)),
        _ => Err(DeviceError::InvalidData),
    }
}

fn asymmetric_key_material(
    algorithm: Algorithm,
    generate: bool,
    supplied: &[u8],
) -> Result<ObjectMaterial> {
    let expected_length = algorithm
        .asymmetric_key_length()
        .ok_or(DeviceError::InvalidData)?;
    if let Some(parameters) = algorithm.ml_kem() {
        if generate && !supplied.is_empty() || !generate && supplied.len() != 64 {
            return Err(DeviceError::WrongLength);
        }
        let key = if generate {
            software_key_core::post_quantum::MlKemPrivateKey::generate(parameters)
        } else {
            software_key_core::post_quantum::MlKemPrivateKey::from_seed_slice(parameters, supplied)
        }
        .map_err(|_| DeviceError::InvalidData)?;
        return Ok(ObjectMaterial::MlKemKey(key));
    }
    if generate && !supplied.is_empty() {
        return Err(DeviceError::WrongLength);
    }
    if matches!(algorithm, Algorithm::X25519 | Algorithm::X448) {
        let curve = if algorithm == Algorithm::X25519 {
            MontgomeryCurve::X25519
        } else {
            MontgomeryCurve::X448
        };
        let key = if generate {
            SoftwareMontgomeryKey::generate(curve).map_err(|_| DeviceError::StorageFailed)?
        } else {
            if supplied.len() != expected_length {
                return Err(DeviceError::WrongLength);
            }
            SoftwareMontgomeryKey::from_serialized(curve, supplied)
                .map_err(|_| DeviceError::InvalidData)?
        };
        return Ok(ObjectMaterial::MontgomeryKey(key));
    }
    if algorithm.is_rsa_key() {
        let key = if generate {
            SoftwareSigningKey::generate_for_kind(KeyKind::Rsa {
                modulus_bits: expected_length * 8,
            })
            .map_err(|_| DeviceError::StorageFailed)?
        } else {
            if supplied.len() != expected_length {
                return Err(DeviceError::WrongLength);
            }
            let (p, q) = supplied.split_at(expected_length / 2);
            SoftwareSigningKey::from_rsa_primes(p, q, &[1, 0, 1])
                .map_err(|_| DeviceError::InvalidData)?
        };
        return Ok(ObjectMaterial::SigningKey(key));
    }
    let key_kind = asymmetric_key_kind(algorithm)?;
    let key = if generate {
        SoftwareSigningKey::generate_for_kind(key_kind).map_err(|_| DeviceError::StorageFailed)?
    } else {
        if supplied.len() != expected_length {
            return Err(DeviceError::WrongLength);
        }
        SoftwareSigningKey::from_serialized_for_kind(key_kind, supplied)
            .map_err(|_| DeviceError::InvalidData)?
    };
    if key.serialized().map_or(0, |secret| secret.len()) != expected_length {
        return Err(DeviceError::InvalidData);
    }
    Ok(ObjectMaterial::SigningKey(key))
}

fn asymmetric_key_kind(algorithm: Algorithm) -> Result<KeyKind> {
    if let Some(parameters) = algorithm.ml_dsa() {
        return Ok(KeyKind::MlDsa(parameters));
    }
    Ok(match algorithm {
        Algorithm::EcP224 => KeyKind::Ec(EcCurve::P224),
        Algorithm::EcP256 => KeyKind::Ec(EcCurve::P256),
        Algorithm::EcP384 => KeyKind::Ec(EcCurve::P384),
        Algorithm::EcP521 => KeyKind::Ec(EcCurve::P521),
        Algorithm::EcK256 => KeyKind::Ec(EcCurve::Secp256k1),
        Algorithm::EcBrainpoolP256 => KeyKind::Ec(EcCurve::BrainpoolP256),
        Algorithm::EcBrainpoolP384 => KeyKind::Ec(EcCurve::BrainpoolP384),
        Algorithm::EcBrainpoolP512 => KeyKind::Ec(EcCurve::BrainpoolP512),
        Algorithm::Ed25519 => KeyKind::Edwards(EdwardsCurve::Ed25519),
        Algorithm::Ed448 => KeyKind::Edwards(EdwardsCurve::Ed448),
        Algorithm::Rsa2048 => KeyKind::Rsa { modulus_bits: 2048 },
        Algorithm::Rsa3072 => KeyKind::Rsa { modulus_bits: 3072 },
        Algorithm::Rsa4096 => KeyKind::Rsa { modulus_bits: 4096 },
        _ => return Err(DeviceError::InvalidData),
    })
}

fn import_rsa_wrapped_key_material(
    object_type: ObjectType,
    algorithm: Algorithm,
    plaintext: &[u8],
) -> Result<(ObjectMaterial, usize)> {
    match object_type {
        ObjectType::AsymmetricKey => {
            let material = asymmetric_material_from_pkcs8(algorithm, plaintext)?;
            let logical_length = algorithm
                .asymmetric_key_length()
                .ok_or(DeviceError::InvalidData)?;
            if material.len() != logical_length {
                return Err(DeviceError::InvalidData);
            }
            Ok((material, logical_length))
        }
        ObjectType::SymmetricKey => {
            let key_length = match algorithm {
                Algorithm::Aes128 | Algorithm::Aes192 | Algorithm::Aes256 => {
                    algorithm.aes_key_length().unwrap()
                }
                _ => return Err(DeviceError::InvalidData),
            };
            if plaintext.len() != key_length {
                return Err(DeviceError::WrongLength);
            }
            Ok((ObjectMaterial::Secret(plaintext.to_vec()), key_length))
        }
        _ => Err(DeviceError::InvalidData),
    }
}

fn signing_key(object: &ObjectRecord) -> Result<&SoftwareSigningKey> {
    let ObjectMaterial::SigningKey(key) = &object.material else {
        return Err(DeviceError::InvalidData);
    };
    let algorithm = Algorithm::from_byte(object.info.algorithm).ok_or(DeviceError::InvalidData)?;
    if matches!(algorithm, Algorithm::X25519 | Algorithm::X448)
        || algorithm.is_rsa_key() != matches!(key, SoftwareSigningKey::Rsa(_))
    {
        return Err(DeviceError::InvalidData);
    }
    Ok(key)
}

fn rsa_modulus_length(object: &ObjectRecord) -> Result<usize> {
    Algorithm::from_byte(object.info.algorithm)
        .filter(|algorithm| algorithm.is_rsa_key())
        .and_then(Algorithm::asymmetric_key_length)
        .ok_or(DeviceError::InvalidData)
}

fn object_subject_public_key_info(object: &ObjectRecord) -> Result<SubjectPublicKeyInfoOwned> {
    if let Some((curve, oid)) = montgomery_algorithm(object.info.algorithm) {
        return Ok(SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(
                &montgomery_key_for_curve(object, curve)?.public_key(),
            )
            .map_err(|_| DeviceError::InvalidData)?,
        });
    }
    let public_key = signing_key(object)?.public_key();
    if matches!(public_key, SoftwarePublicKey::MlDsa { .. }) {
        return Err(DeviceError::InvalidData);
    }
    subject_public_key_info(&public_key).map_err(|_| DeviceError::InvalidData)
}

fn attestation_metadata_extensions(
    config: &DeviceConfig,
    target: &ObjectInfo,
) -> Result<Vec<Extension>> {
    const PREFIX: &str = "1.3.6.1.4.1.41482.4";
    let values = [
        (1, config.version.to_vec()),
        (2, config.serial.to_be_bytes().to_vec()),
        (3, vec![target.origin]),
        (4, target.domains.to_be_bytes().to_vec()),
        (5, target.capabilities.to_bytes().to_vec()),
        (6, target.id.to_be_bytes().to_vec()),
        (9, target.label.clone()),
    ];
    values
        .into_iter()
        .map(|(suffix, value)| {
            Ok(Extension {
                extn_id: ObjectIdentifier::new(&format!("{PREFIX}.{suffix}"))
                    .map_err(|_| DeviceError::InvalidData)?,
                critical: false,
                extn_value: OctetString::new(value).map_err(|_| DeviceError::InvalidData)?,
            })
        })
        .collect()
}

fn rsa_key(object: &ObjectRecord) -> Result<&SoftwareSigningKey> {
    let algorithm = Algorithm::from_byte(object.info.algorithm).ok_or(DeviceError::InvalidData)?;
    if !algorithm.is_rsa_key() {
        return Err(DeviceError::InvalidData);
    }
    signing_key(object)
}

fn montgomery_algorithm(algorithm: u8) -> Option<(MontgomeryCurve, ObjectIdentifier)> {
    match Algorithm::from_byte(algorithm) {
        Some(Algorithm::X25519) => Some((
            MontgomeryCurve::X25519,
            ObjectIdentifier::new_unwrap("1.3.101.110"),
        )),
        Some(Algorithm::X448) => Some((
            MontgomeryCurve::X448,
            ObjectIdentifier::new_unwrap("1.3.101.111"),
        )),
        _ => None,
    }
}

fn montgomery_key(object: &ObjectRecord) -> Result<&SoftwareMontgomeryKey> {
    let (curve, _) = montgomery_algorithm(object.info.algorithm).ok_or(DeviceError::InvalidData)?;
    montgomery_key_for_curve(object, curve)
}

fn montgomery_key_for_curve(
    object: &ObjectRecord,
    curve: MontgomeryCurve,
) -> Result<&SoftwareMontgomeryKey> {
    let ObjectMaterial::MontgomeryKey(key) = &object.material else {
        return Err(DeviceError::InvalidData);
    };
    if key.curve() != curve {
        return Err(DeviceError::InvalidData);
    }
    Ok(key)
}

fn object_secret(object: &ObjectRecord) -> Result<&[u8]> {
    match &object.material {
        ObjectMaterial::Secret(secret) => Ok(secret),
        _ => Err(DeviceError::InvalidData),
    }
}

fn otp_aead_material(object: &ObjectRecord) -> Result<(&[u8; 4], &[u8])> {
    match &object.material {
        ObjectMaterial::OtpAeadKey { nonce_id, key } => Ok((nonce_id, key)),
        _ => Err(DeviceError::InvalidData),
    }
}

fn otp_aead_encrypt(object: &ObjectRecord, credential: &[u8]) -> Result<Vec<u8>> {
    if credential.len() != 22 {
        return Err(DeviceError::WrongLength);
    }
    let (nonce_id, key) = otp_aead_material(object)?;
    let mut nonce = [0; AES_CCM_NONCE_SIZE];
    nonce[..4].copy_from_slice(nonce_id);
    getrandom::fill(&mut nonce[4..10]).map_err(|_| DeviceError::StorageFailed)?;
    let encrypted =
        encrypt_yubico_otp_aead(key, &nonce, credential).map_err(|_| DeviceError::InvalidData)?;
    Ok([&nonce[4..10], encrypted.as_slice()].concat())
}

fn otp_aead_decrypt(object: &ObjectRecord, aead: &[u8]) -> Result<Vec<u8>> {
    if aead.len() != 36 {
        return Err(DeviceError::WrongLength);
    }
    let (nonce_id, key) = otp_aead_material(object)?;
    let mut nonce = [0; AES_CCM_NONCE_SIZE];
    nonce[..4].copy_from_slice(nonce_id);
    nonce[4..10].copy_from_slice(&aead[..6]);
    decrypt_yubico_otp_aead(key, &nonce, &aead[6..]).map_err(|_| DeviceError::InvalidOtp)
}

fn yubico_crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffff_u16;
    for byte in data {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct Rfc8410PrivateKeyInfo {
    version: u8,
    private_key_algorithm: AlgorithmIdentifierOwned,
    private_key: OctetString,
}

fn montgomery_pkcs8(
    curve: MontgomeryCurve,
    oid: ObjectIdentifier,
    secret: &[u8],
) -> Result<Vec<u8>> {
    SoftwareMontgomeryKey::from_serialized(curve, secret).map_err(|_| DeviceError::InvalidData)?;
    let inner = OctetString::new(secret.to_vec())
        .map_err(|_| DeviceError::InvalidData)?
        .to_der()
        .map_err(|_| DeviceError::InvalidData)?;
    Rfc8410PrivateKeyInfo {
        version: 0,
        private_key_algorithm: AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        },
        private_key: OctetString::new(inner).map_err(|_| DeviceError::InvalidData)?,
    }
    .to_der()
    .map_err(|_| DeviceError::InvalidData)
}

fn montgomery_from_pkcs8(
    curve: MontgomeryCurve,
    oid: ObjectIdentifier,
    encoded: &[u8],
) -> Result<Vec<u8>> {
    let info = Rfc8410PrivateKeyInfo::from_der(encoded).map_err(|_| DeviceError::InvalidData)?;
    if info.version != 0
        || info.private_key_algorithm.oid != oid
        || info.private_key_algorithm.parameters.is_some()
    {
        return Err(DeviceError::InvalidData);
    }
    let secret = OctetString::from_der(info.private_key.as_bytes())
        .map_err(|_| DeviceError::InvalidData)?
        .as_bytes()
        .to_vec();
    SoftwareMontgomeryKey::from_serialized(curve, &secret).map_err(|_| DeviceError::InvalidData)?;
    Ok(secret)
}

fn asymmetric_pkcs8(object: &ObjectRecord) -> Result<Vec<u8>> {
    if let Some((curve, oid)) = montgomery_algorithm(object.info.algorithm) {
        return montgomery_pkcs8(
            curve,
            oid,
            &montgomery_key_for_curve(object, curve)?.serialized(),
        );
    }
    signing_key(object)?
        .to_pkcs8_der()
        .map(|encoded| encoded.to_vec())
        .map_err(|_| DeviceError::InvalidData)
}

fn asymmetric_material_from_pkcs8(algorithm: Algorithm, encoded: &[u8]) -> Result<ObjectMaterial> {
    if let Some((curve, oid)) = montgomery_algorithm(algorithm as u8) {
        let serialized = montgomery_from_pkcs8(curve, oid, encoded)?;
        return SoftwareMontgomeryKey::from_serialized(curve, &serialized)
            .map(ObjectMaterial::MontgomeryKey)
            .map_err(|_| DeviceError::InvalidData);
    }
    let key = SoftwareSigningKey::from_pkcs8_der_for_kind(asymmetric_key_kind(algorithm)?, encoded)
        .map_err(|_| DeviceError::InvalidData)?;
    if algorithm.is_rsa_key() {
        let SoftwarePublicKey::Rsa { modulus, exponent } = key.public_key() else {
            return Err(DeviceError::InvalidData);
        };
        if exponent != [1, 0, 1] || algorithm.asymmetric_key_length() != Some(modulus.len()) {
            return Err(DeviceError::InvalidData);
        }
        return Ok(ObjectMaterial::SigningKey(key));
    }
    if algorithm.asymmetric_key_length() != key.private_value().as_deref().map(Vec::len) {
        return Err(DeviceError::InvalidData);
    }
    Ok(ObjectMaterial::SigningKey(key))
}

fn validate_wrapped_object(object: &ObjectRecord) -> Result<()> {
    object.validate()?;
    let algorithm = Algorithm::from_byte(object.info.algorithm).ok_or(DeviceError::InvalidData)?;
    let valid = match (&object.info.object_type, &object.material) {
        (ObjectType::Opaque, ObjectMaterial::Opaque(_)) => {
            matches!(
                algorithm,
                Algorithm::OpaqueData | Algorithm::OpaqueX509Certificate
            )
        }
        (ObjectType::Template, ObjectMaterial::Opaque(_)) => algorithm == Algorithm::TemplateSsh,
        (ObjectType::AuthenticationKey, ObjectMaterial::Authentication(authentication)) => {
            parse_authentication_key_material(
                object.info.algorithm,
                match authentication {
                    AuthenticationKeyMaterial::Symmetric(value)
                    | AuthenticationKeyMaterial::Asymmetric(value) => value,
                },
            )
            .is_ok_and(|parsed| &parsed == authentication)
        }
        (ObjectType::AsymmetricKey, ObjectMaterial::SigningKey(value)) => {
            !matches!(algorithm, Algorithm::X25519 | Algorithm::X448)
                && algorithm.asymmetric_key_length()
                    == Some(value.private_value().map_or_else(
                        || algorithm.asymmetric_key_length().unwrap_or_default(),
                        |private| private.len(),
                    ))
        }
        (ObjectType::AsymmetricKey, ObjectMaterial::MontgomeryKey(_)) => {
            matches!(algorithm, Algorithm::X25519 | Algorithm::X448)
        }
        (ObjectType::WrapKey, ObjectMaterial::SigningKey(value)) if algorithm.is_rsa_key() => {
            matches!(value, SoftwareSigningKey::Rsa(_))
        }
        (ObjectType::WrapKey, ObjectMaterial::Secret(value)) => {
            matches!(
                algorithm,
                Algorithm::Aes128CcmWrap | Algorithm::Aes192CcmWrap | Algorithm::Aes256CcmWrap
            ) && algorithm.aes_key_length() == Some(value.len())
        }
        (ObjectType::HmacKey, ObjectMaterial::Secret(value)) => {
            algorithm.hmac_object_length().is_some() && (1..=128).contains(&value.len())
        }
        (ObjectType::OtpAeadKey, ObjectMaterial::OtpAeadKey { key, .. }) => {
            matches!(
                algorithm,
                Algorithm::Aes128YubicoOtp
                    | Algorithm::Aes192YubicoOtp
                    | Algorithm::Aes256YubicoOtp
            ) && algorithm.aes_key_length() == Some(key.len())
        }
        (ObjectType::SymmetricKey, ObjectMaterial::Secret(value)) => {
            matches!(
                algorithm,
                Algorithm::Aes128 | Algorithm::Aes192 | Algorithm::Aes256
            ) && algorithm.aes_key_length() == Some(value.len())
        }
        (ObjectType::PublicWrapKey, ObjectMaterial::Public(value)) => {
            algorithm.is_rsa_key() && algorithm.asymmetric_key_length() == Some(value.len())
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(DeviceError::InvalidData)
    }
}

fn wrapped_material(object: &ObjectRecord) -> Result<CborValue> {
    let (kind, values) = match (&object.info.object_type, &object.material) {
        (ObjectType::AsymmetricKey, ObjectMaterial::SigningKey(_))
        | (ObjectType::AsymmetricKey, ObjectMaterial::MontgomeryKey(_))
        | (ObjectType::WrapKey, ObjectMaterial::SigningKey(_))
            if Algorithm::from_byte(object.info.algorithm).is_some_and(Algorithm::is_rsa_key)
                || object.info.object_type == ObjectType::AsymmetricKey =>
        {
            (
                WRAPPED_MATERIAL_PKCS8,
                vec![CborValue::Bytes(asymmetric_pkcs8(object)?)],
            )
        }
        (
            ObjectType::WrapKey | ObjectType::HmacKey | ObjectType::SymmetricKey,
            ObjectMaterial::Secret(value),
        ) => (
            WRAPPED_MATERIAL_SECRET,
            vec![CborValue::Bytes(value.clone())],
        ),
        (ObjectType::Opaque | ObjectType::Template, ObjectMaterial::Opaque(value)) => (
            WRAPPED_MATERIAL_OPAQUE,
            vec![CborValue::Bytes(value.clone())],
        ),
        (ObjectType::PublicWrapKey, ObjectMaterial::Public(value)) => (
            WRAPPED_MATERIAL_PUBLIC,
            vec![CborValue::Bytes(value.clone())],
        ),
        (
            ObjectType::AuthenticationKey,
            ObjectMaterial::Authentication(AuthenticationKeyMaterial::Symmetric(value)),
        ) => (
            WRAPPED_MATERIAL_AUTHENTICATION_SYMMETRIC,
            vec![CborValue::Bytes(value.clone())],
        ),
        (
            ObjectType::AuthenticationKey,
            ObjectMaterial::Authentication(AuthenticationKeyMaterial::Asymmetric(value)),
        ) => (
            WRAPPED_MATERIAL_AUTHENTICATION_ASYMMETRIC,
            vec![CborValue::Bytes(value.clone())],
        ),
        (ObjectType::OtpAeadKey, ObjectMaterial::OtpAeadKey { nonce_id, key }) => (
            WRAPPED_MATERIAL_OTP_AEAD,
            vec![
                CborValue::Bytes(nonce_id.to_vec()),
                CborValue::Bytes(key.clone()),
            ],
        ),
        _ => return Err(DeviceError::InvalidData),
    };
    Ok(CborValue::Array(
        [vec![CborValue::Integer(kind.into())], values].concat(),
    ))
}

fn encode_wrapped_object(object: &ObjectRecord) -> Result<Vec<u8>> {
    validate_wrapped_object(object)?;
    let value = CborValue::Array(vec![
        CborValue::Text(WRAPPED_OBJECT_SCHEMA.to_owned()),
        CborValue::Integer(WRAPPED_OBJECT_VERSION.into()),
        CborValue::Integer((object.info.object_type as u8).into()),
        CborValue::Integer(object.info.id.into()),
        CborValue::Integer(object.info.domains.into()),
        CborValue::Bytes(object.info.capabilities.to_bytes().to_vec()),
        CborValue::Integer(object.info.algorithm.into()),
        CborValue::Integer((object.info.origin & 0x0f).into()),
        CborValue::Bytes(object.info.label.clone()),
        CborValue::Bytes(object.info.delegated_capabilities.to_bytes().to_vec()),
        wrapped_material(object)?,
    ]);
    let mut output = Vec::new();
    ciborium::into_writer(&value, &mut output).map_err(|_| DeviceError::StorageFailed)?;
    if output.len() > usize::from(u16::MAX) {
        return Err(DeviceError::WrongLength);
    }
    Ok(output)
}

fn wrapped_u8(value: CborValue) -> Result<u8> {
    value
        .into_integer()
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(DeviceError::InvalidData)
}

fn wrapped_u16(value: CborValue) -> Result<u16> {
    value
        .into_integer()
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(DeviceError::InvalidData)
}

fn wrapped_bytes(value: CborValue) -> Result<Vec<u8>> {
    value.into_bytes().map_err(|_| DeviceError::InvalidData)
}

fn decode_wrapped_material(
    object_type: ObjectType,
    algorithm: Algorithm,
    value: CborValue,
) -> Result<ObjectMaterial> {
    let CborValue::Array(values) = value else {
        return Err(DeviceError::InvalidData);
    };
    let mut values = values.into_iter();
    let kind = wrapped_u8(values.next().ok_or(DeviceError::InvalidData)?)?;
    let material = match kind {
        WRAPPED_MATERIAL_SECRET
            if matches!(
                object_type,
                ObjectType::WrapKey | ObjectType::HmacKey | ObjectType::SymmetricKey
            ) && !(object_type == ObjectType::WrapKey && algorithm.is_rsa_key()) =>
        {
            ObjectMaterial::Secret(wrapped_bytes(
                values.next().ok_or(DeviceError::InvalidData)?,
            )?)
        }
        WRAPPED_MATERIAL_PKCS8
            if object_type == ObjectType::AsymmetricKey
                || object_type == ObjectType::WrapKey && algorithm.is_rsa_key() =>
        {
            let encoded = wrapped_bytes(values.next().ok_or(DeviceError::InvalidData)?)?;
            asymmetric_material_from_pkcs8(algorithm, &encoded)?
        }
        WRAPPED_MATERIAL_OPAQUE
            if matches!(object_type, ObjectType::Opaque | ObjectType::Template) =>
        {
            ObjectMaterial::Opaque(wrapped_bytes(
                values.next().ok_or(DeviceError::InvalidData)?,
            )?)
        }
        WRAPPED_MATERIAL_PUBLIC if object_type == ObjectType::PublicWrapKey => {
            ObjectMaterial::Public(wrapped_bytes(
                values.next().ok_or(DeviceError::InvalidData)?,
            )?)
        }
        WRAPPED_MATERIAL_AUTHENTICATION_SYMMETRIC
            if object_type == ObjectType::AuthenticationKey =>
        {
            ObjectMaterial::Authentication(AuthenticationKeyMaterial::Symmetric(wrapped_bytes(
                values.next().ok_or(DeviceError::InvalidData)?,
            )?))
        }
        WRAPPED_MATERIAL_AUTHENTICATION_ASYMMETRIC
            if object_type == ObjectType::AuthenticationKey =>
        {
            ObjectMaterial::Authentication(AuthenticationKeyMaterial::Asymmetric(wrapped_bytes(
                values.next().ok_or(DeviceError::InvalidData)?,
            )?))
        }
        WRAPPED_MATERIAL_OTP_AEAD if object_type == ObjectType::OtpAeadKey => {
            let nonce_id: [u8; 4] = wrapped_bytes(values.next().ok_or(DeviceError::InvalidData)?)?
                .try_into()
                .map_err(|_| DeviceError::InvalidData)?;
            let key = wrapped_bytes(values.next().ok_or(DeviceError::InvalidData)?)?;
            ObjectMaterial::OtpAeadKey { nonce_id, key }
        }
        _ => return Err(DeviceError::InvalidData),
    };
    if values.next().is_some() {
        return Err(DeviceError::InvalidData);
    }
    Ok(material)
}

fn decode_wrapped_object(data: &[u8]) -> Result<ObjectRecord> {
    if data.len() > usize::from(u16::MAX) {
        return Err(DeviceError::WrongLength);
    }
    let mut input = Cursor::new(data);
    let value: CborValue =
        ciborium::from_reader(&mut input).map_err(|_| DeviceError::InvalidData)?;
    if input.position() != data.len() as u64 {
        return Err(DeviceError::InvalidData);
    }
    let CborValue::Array(fields) = value else {
        return Err(DeviceError::InvalidData);
    };
    if fields.len() != 11 {
        return Err(DeviceError::InvalidData);
    }
    let mut fields = fields.into_iter();
    if fields.next() != Some(CborValue::Text(WRAPPED_OBJECT_SCHEMA.to_owned()))
        || wrapped_u8(fields.next().ok_or(DeviceError::InvalidData)?)? != WRAPPED_OBJECT_VERSION
    {
        return Err(DeviceError::InvalidData);
    }
    let object_type =
        ObjectType::from_byte(wrapped_u8(fields.next().ok_or(DeviceError::InvalidData)?)?)
            .ok_or(DeviceError::InvalidData)?;
    let id = wrapped_u16(fields.next().ok_or(DeviceError::InvalidData)?)?;
    let domains = wrapped_u16(fields.next().ok_or(DeviceError::InvalidData)?)?;
    let capabilities = CapabilitySet::from_bytes(
        wrapped_bytes(fields.next().ok_or(DeviceError::InvalidData)?)?
            .try_into()
            .map_err(|_| DeviceError::InvalidData)?,
    );
    let algorithm_byte = wrapped_u8(fields.next().ok_or(DeviceError::InvalidData)?)?;
    let algorithm = Algorithm::from_byte(algorithm_byte).ok_or(DeviceError::InvalidData)?;
    let origin = wrapped_u8(fields.next().ok_or(DeviceError::InvalidData)?)?;
    if origin & 0xf0 != 0 {
        return Err(DeviceError::InvalidData);
    }
    let label = wrapped_bytes(fields.next().ok_or(DeviceError::InvalidData)?)?;
    let delegated_capabilities = CapabilitySet::from_bytes(
        wrapped_bytes(fields.next().ok_or(DeviceError::InvalidData)?)?
            .try_into()
            .map_err(|_| DeviceError::InvalidData)?,
    );
    let material = decode_wrapped_material(
        object_type,
        algorithm,
        fields.next().ok_or(DeviceError::InvalidData)?,
    )?;
    let mut record = ObjectRecord {
        info: ObjectInfo {
            capabilities,
            id,
            length: 0,
            domains,
            object_type,
            algorithm: algorithm_byte,
            sequence: 0,
            origin,
            label,
            delegated_capabilities,
        },
        material,
    };
    record.normalize_info_length()?;
    record.validate()?;
    if encode_wrapped_object(&record)? != data {
        return Err(DeviceError::InvalidData);
    }
    Ok(record)
}

fn rsa_oaep_hash(algorithm: u8) -> Result<RsaHashAlgorithm> {
    match Algorithm::from_byte(algorithm) {
        Some(Algorithm::RsaOaepSha1) => Ok(RsaHashAlgorithm::Sha1),
        Some(Algorithm::RsaOaepSha256) => Ok(RsaHashAlgorithm::Sha256),
        Some(Algorithm::RsaOaepSha384) => Ok(RsaHashAlgorithm::Sha384),
        Some(Algorithm::RsaOaepSha512) => Ok(RsaHashAlgorithm::Sha512),
        _ => Err(DeviceError::InvalidData),
    }
}

fn rsa_wrap_aes_length(algorithm: u8) -> Result<usize> {
    match Algorithm::from_byte(algorithm) {
        Some(Algorithm::Aes128) => Ok(16),
        Some(Algorithm::Aes192) => Ok(24),
        Some(Algorithm::Aes256) => Ok(32),
        _ => Err(DeviceError::InvalidData),
    }
}

fn rsa_aes_wrap(
    public_key: &SoftwarePublicKey,
    aes_length: usize,
    plaintext: &[u8],
    label_digest: &[u8],
    mgf_hash: RsaHashAlgorithm,
) -> Result<Vec<u8>> {
    let mut aes_key = Zeroizing::new(vec![0; aes_length]);
    getrandom::fill(&mut aes_key).map_err(|_| DeviceError::StorageFailed)?;
    let encrypted_key = public_key
        .encrypt_rsa_oaep_digest(&aes_key, label_digest, mgf_hash)
        .map_err(|_| DeviceError::InvalidData)?;
    let wrapped = wrap_aes_kwp(&aes_key, plaintext).map_err(|_| DeviceError::InvalidData)?;
    Ok([encrypted_key.as_slice(), wrapped.as_slice()].concat())
}

fn rsa_aes_unwrap(
    private_key: &SoftwareSigningKey,
    wrapped: &[u8],
    modulus_length: usize,
    label_digest: &[u8],
    mgf_hash: RsaHashAlgorithm,
) -> Result<Vec<u8>> {
    if wrapped.len() <= modulus_length {
        return Err(DeviceError::WrongLength);
    }
    let aes_key = private_key
        .decrypt_rsa_oaep_digest(&wrapped[..modulus_length], label_digest, mgf_hash)
        .map_err(|_| DeviceError::InvalidData)?;
    if !matches!(aes_key.len(), 16 | 24 | 32) {
        return Err(DeviceError::InvalidData);
    }
    unwrap_aes_kwp(&aes_key, &wrapped[modulus_length..]).map_err(|_| DeviceError::InvalidData)
}

fn rsa_hash_from_digest_length(length: usize) -> Option<RsaHashAlgorithm> {
    match length {
        20 => Some(RsaHashAlgorithm::Sha1),
        32 => Some(RsaHashAlgorithm::Sha256),
        48 => Some(RsaHashAlgorithm::Sha384),
        64 => Some(RsaHashAlgorithm::Sha512),
        _ => None,
    }
}

fn rsa_mgf_hash(algorithm: u8) -> Result<RsaHashAlgorithm> {
    match Algorithm::from_byte(algorithm) {
        Some(Algorithm::Mgf1Sha1) => Ok(RsaHashAlgorithm::Sha1),
        Some(Algorithm::Mgf1Sha256) => Ok(RsaHashAlgorithm::Sha256),
        Some(Algorithm::Mgf1Sha384) => Ok(RsaHashAlgorithm::Sha384),
        Some(Algorithm::Mgf1Sha512) => Ok(RsaHashAlgorithm::Sha512),
        _ => Err(DeviceError::InvalidData),
    }
}

fn hmac_length(algorithm: u8) -> Result<usize> {
    match algorithm {
        19 => Ok(20),
        20 => Ok(32),
        21 => Ok(48),
        22 => Ok(64),
        _ => Err(DeviceError::InvalidData),
    }
}

fn calculate_hmac(object: &ObjectRecord, data: &[u8]) -> Result<Vec<u8>> {
    let ObjectMaterial::Secret(secret) = &object.material else {
        return Err(DeviceError::InvalidData);
    };
    let algorithm = match object.info.algorithm {
        19 => software_key_core::digest::HashAlgorithm::Sha1,
        20 => software_key_core::digest::HashAlgorithm::Sha256,
        21 => software_key_core::digest::HashAlgorithm::Sha384,
        22 => software_key_core::digest::HashAlgorithm::Sha512,
        _ => return Err(DeviceError::InvalidData),
    };
    software_key_core::digest::hmac(algorithm, secret, data).map_err(|_| DeviceError::InvalidData)
}

fn raw_ecdh_secret(object: &ObjectRecord, peer_public: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if montgomery_algorithm(object.info.algorithm).is_some() {
        montgomery_key(object)?
            .derive(peer_public)
            .map_err(|_| DeviceError::InvalidData)
    } else {
        derive_with_signing_key(signing_key(object)?, peer_public)
            .map_err(|_| DeviceError::InvalidData)
    }
}

fn ecdh_kdf_hash(value: u8) -> Result<HashAlgorithm> {
    match value {
        1 => Ok(HashAlgorithm::Sha1),
        2 => Ok(HashAlgorithm::Sha224),
        3 => Ok(HashAlgorithm::Sha256),
        4 => Ok(HashAlgorithm::Sha384),
        5 => Ok(HashAlgorithm::Sha512),
        6 => Ok(HashAlgorithm::Sha3_224),
        7 => Ok(HashAlgorithm::Sha3_256),
        8 => Ok(HashAlgorithm::Sha3_384),
        9 => Ok(HashAlgorithm::Sha3_512),
        _ => Err(DeviceError::InvalidData),
    }
}

fn validate_session_flags(flags: u8) -> Result<()> {
    if flags & !(FLAG_READABLE | FLAG_DERIVE | FLAG_VERIFY) == 0 {
        Ok(())
    } else {
        Err(DeviceError::InvalidData)
    }
}

fn validate_session_result_header(header: SessionResultHeader) -> Result<usize> {
    validate_session_flags(header.flags)?;
    if header.kind == SessionObjectKind::P256Private {
        return Err(DeviceError::InvalidData);
    }
    let output_length = usize::from(header.output_length);
    if output_length == 0 || output_length > 1024 {
        return Err(DeviceError::WrongLength);
    }
    Ok(output_length)
}

fn session_derivation_secret(objects: &SessionObjects, handle: u64) -> Result<Zeroizing<Vec<u8>>> {
    let object = objects.get(handle).ok_or(DeviceError::ObjectNotFound)?;
    if object.flags & FLAG_DERIVE == 0 {
        return Err(DeviceError::InsufficientPermissions);
    }
    object
        .secret_value()
        .map(|value| Zeroizing::new(value.to_vec()))
        .ok_or(DeviceError::InvalidData)
}

fn trim_label(label: &[u8]) -> Vec<u8> {
    label
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default()
        .to_vec()
}

fn valid_option_value(value: u8) -> bool {
    matches!(value, OPTION_OFF | OPTION_ON | OPTION_FIX)
}

fn set_option_value(current: &mut u8, requested: u8) -> Result<()> {
    if !valid_option_value(requested) {
        return Err(DeviceError::InvalidData);
    }
    if *current == OPTION_FIX && requested != OPTION_FIX {
        return Err(DeviceError::InsufficientPermissions);
    }
    *current = requested;
    Ok(())
}

fn fips_disallowed_algorithm(algorithm: u8) -> bool {
    matches!(
        Algorithm::from_byte(algorithm),
        Some(
            Algorithm::RsaPkcs1Sha1
                | Algorithm::RsaPssSha1
                | Algorithm::EcdsaSha1
                | Algorithm::EcK256
                | Algorithm::RsaPkcs1Decrypt
        )
    )
}

fn command_changes_persistent_state(command: CommandCode) -> bool {
    matches!(
        command,
        CommandCode::PutOpaque
            | CommandCode::PutAuthenticationKey
            | CommandCode::PutAsymmetricKey
            | CommandCode::GenerateAsymmetricKey
            | CommandCode::ImportWrapped
            | CommandCode::PutWrapKey
            | CommandCode::SetOption
            | CommandCode::PutHmacKey
            | CommandCode::GenerateHmacKey
            | CommandCode::GenerateWrapKey
            | CommandCode::DeleteObject
            | CommandCode::PutTemplate
            | CommandCode::PutOtpAeadKey
            | CommandCode::GenerateOtpAeadKey
            | CommandCode::SetLogIndex
            | CommandCode::ChangeAuthenticationKey
            | CommandCode::PutSymmetricKey
            | CommandCode::GenerateSymmetricKey
            | CommandCode::PutPublicWrapKey
            | CommandCode::PutRsaWrappedKey
            | CommandCode::ImportRsaWrapped
            | CommandCode::ResetDevice
    )
}

fn command_is_meta(command: CommandCode) -> bool {
    matches!(
        command,
        CommandCode::Echo
            | CommandCode::CreateSession
            | CommandCode::AuthenticateSession
            | CommandCode::SessionMessage
            | CommandCode::GetDeviceInfo
            | CommandCode::GetDevicePublicKey
            | CommandCode::CloseSession
    )
}

fn command_can_be_audited(command: CommandCode) -> bool {
    !command_is_meta(command)
        || matches!(
            command,
            CommandCode::CreateSession | CommandCode::AuthenticateSession
        )
}

fn audit_key_ids(command: CommandCode, data: &[u8]) -> (u16, u16) {
    match command {
        CommandCode::SignAttestationCertificate => {
            decode_request::<SignAttestationCertificateRequest>(data)
                .map(|request| (request.target_id, request.attesting_id))
                .unwrap_or_default()
        }
        CommandCode::RewrapOtpAead => decode_request::<RewrapOtpAeadRequest>(data)
            .map(|request| (request.from_id, request.to_id))
            .unwrap_or_default(),
        CommandCode::ExportWrapped => decode_request::<ExportWrappedRequest>(data)
            .map(|request| (request.target.id, request.wrap_id))
            .unwrap_or_default(),
        CommandCode::ExportRsaWrapped => decode_request::<ExportRsaWrappedRequest>(data)
            .map(|request| (request.0.target.id, request.0.wrap_id))
            .unwrap_or_default(),
        _ => {
            let mut reader = WireReader::new(data);
            (reader.read_u16().unwrap_or_default(), 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_channel_crypto::{
        BLOCK_SIZE, cbc_decrypt, cbc_encrypt, cmac, encrypt_block, pad, scp03_kdf, unpad,
    };
    #[cfg(any(
        feature = "firmware-secure-channel",
        feature = "firmware-full",
        feature = "test-firmware-prefixed-ecdh",
        feature = "test-firmware-session-objects"
    ))]
    use p256::ecdh::diffie_hellman;
    use p256::elliptic_curve::sec1::ToSec1Point;
    use rsa::{BigUint, RsaPublicKey};
    #[cfg(any(
        feature = "firmware-secure-channel",
        feature = "firmware-full",
        feature = "test-firmware-session-objects"
    ))]
    use software_key_core::counter_kdf::{CounterKdfField, IntegerFormat, LengthMethod};
    use software_key_core::software_signing::EcCurve;

    fn wrapped_test_record(
        id: u16,
        object_type: ObjectType,
        algorithm: Algorithm,
        material: ObjectMaterial,
    ) -> ObjectRecord {
        let mut record = ObjectRecord {
            info: ObjectInfo {
                capabilities: CapabilitySet::from_capabilities([
                    Capability::ExportableUnderWrap,
                    Capability::DeleteOpaque,
                ]),
                id,
                length: 0,
                domains: 0x8001,
                object_type,
                algorithm: algorithm as u8,
                sequence: 37,
                origin: 0x12,
                label: b"wrapped\0object".to_vec(),
                delegated_capabilities: CapabilitySet::from_capabilities([
                    Capability::GetOpaque,
                    Capability::SignEcdsa,
                ]),
            },
            material,
        };
        record.normalize_info_length().unwrap();
        record
    }

    fn put_opaque_request(id: u16, domains: u16, capabilities: CapabilitySet) -> Frame {
        put_opaque_request_with_payload(id, domains, capabilities, b"payload")
    }

    fn put_opaque_request_with_payload(
        id: u16,
        domains: u16,
        capabilities: CapabilitySet,
        payload: &[u8],
    ) -> Frame {
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(b"state");
        data.resize(42, 0);
        data.extend_from_slice(&domains.to_be_bytes());
        data.extend_from_slice(&capabilities.to_bytes());
        data.push(OPAQUE_DATA_ALGORITHM);
        data.extend_from_slice(payload);
        Frame::new(CommandCode::PutOpaque as u8, data).unwrap()
    }

    fn put_authentication_key_request(
        id: u16,
        domains: u16,
        capabilities: CapabilitySet,
        delegated_capabilities: CapabilitySet,
        key: &[u8],
    ) -> Frame {
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(b"session auth");
        data.resize(42, 0);
        data.extend_from_slice(&domains.to_be_bytes());
        data.extend_from_slice(&capabilities.to_bytes());
        data.push(AUTHENTICATION_ALGORITHM_AES128_YUBICO);
        data.extend_from_slice(&delegated_capabilities.to_bytes());
        data.extend_from_slice(key);
        Frame::new(CommandCode::PutAuthenticationKey as u8, data).unwrap()
    }

    fn put_asymmetric_authentication_key_request(
        id: u16,
        domains: u16,
        capabilities: CapabilitySet,
        delegated_capabilities: CapabilitySet,
        public_key: &[u8],
    ) -> Frame {
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(b"asymmetric auth");
        data.resize(42, 0);
        data.extend_from_slice(&domains.to_be_bytes());
        data.extend_from_slice(&capabilities.to_bytes());
        data.push(AUTHENTICATION_ALGORITHM_EC_P256);
        data.extend_from_slice(&delegated_capabilities.to_bytes());
        data.extend_from_slice(public_key);
        Frame::new(CommandCode::PutAuthenticationKey as u8, data).unwrap()
    }

    #[cfg(any(
        feature = "firmware-secure-channel",
        feature = "firmware-full",
        feature = "test-firmware-prefixed-ecdh"
    ))]
    fn put_asymmetric_key_request(
        id: u16,
        domains: u16,
        capabilities: CapabilitySet,
        algorithm: Algorithm,
        private_key: &[u8],
    ) -> Frame {
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(b"private key");
        data.resize(42, 0);
        data.extend_from_slice(&domains.to_be_bytes());
        data.extend_from_slice(&capabilities.to_bytes());
        data.push(algorithm as u8);
        data.extend_from_slice(private_key);
        Frame::new(CommandCode::PutAsymmetricKey as u8, data).unwrap()
    }

    fn generate_asymmetric_key_request(
        id: u16,
        domains: u16,
        capabilities: CapabilitySet,
        algorithm: u8,
    ) -> Frame {
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(b"signing key");
        data.resize(42, 0);
        data.extend_from_slice(&domains.to_be_bytes());
        data.extend_from_slice(&capabilities.to_bytes());
        data.push(algorithm);
        Frame::new(CommandCode::GenerateAsymmetricKey as u8, data).unwrap()
    }

    fn put_symmetric_key_request(
        id: u16,
        domains: u16,
        capabilities: CapabilitySet,
        algorithm: Algorithm,
        key: &[u8],
    ) -> Frame {
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(b"symmetric key");
        data.resize(42, 0);
        data.extend_from_slice(&domains.to_be_bytes());
        data.extend_from_slice(&capabilities.to_bytes());
        data.push(algorithm as u8);
        data.extend_from_slice(key);
        Frame::new(CommandCode::PutSymmetricKey as u8, data).unwrap()
    }

    #[cfg(any(
        feature = "firmware-secure-channel",
        feature = "firmware-full",
        feature = "test-firmware-session-objects"
    ))]
    fn session_derive_request(
        operation: u8,
        flags: u8,
        kind: SessionObjectKind,
        output_length: u16,
        tail: &[u8],
    ) -> Frame {
        let mut data = vec![operation, flags, kind as u8];
        data.extend_from_slice(&output_length.to_be_bytes());
        data.extend_from_slice(tail);
        Frame::new(CommandCode::SessionObject as u8, data).unwrap()
    }

    #[cfg(any(
        feature = "firmware-secure-channel",
        feature = "firmware-full",
        feature = "test-firmware-session-objects"
    ))]
    fn session_object_handle(response: &Frame) -> u64 {
        assert_eq!(response.command, CommandCode::SessionObject as u8 | 0x80);
        u64::from_be_bytes(response.data[..8].try_into().unwrap())
    }

    #[cfg(any(
        feature = "firmware-secure-channel",
        feature = "firmware-full",
        feature = "test-firmware-session-objects"
    ))]
    fn read_session_object(
        device: &mut Device,
        authorization: SessionAuthorization,
        objects: &mut SessionObjects,
        handle: u64,
    ) -> Frame {
        let mut data = vec![SessionObjectCommand::Read as u8];
        data.extend_from_slice(&handle.to_be_bytes());
        let request = Frame::new(CommandCode::SessionObject as u8, data).unwrap();
        device.execute_inner_with_session(authorization, &request, Some(objects))
    }

    #[test]
    #[cfg(any(
        feature = "firmware-secure-channel",
        feature = "firmware-full",
        feature = "test-firmware-session-objects"
    ))]
    fn volatile_ecdh_objects_are_scoped_protected_and_right_truncated() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let authorization = device.session_authorization(1).unwrap();
        let mut objects = SessionObjects::default();

        let generate = Frame::new(
            CommandCode::SessionObject as u8,
            vec![
                SessionObjectCommand::GenerateAsymmetricKey as u8,
                FLAG_DERIVE,
                Algorithm::EcP256 as u8,
            ],
        )
        .unwrap();
        let generated =
            device.execute_inner_with_session(authorization, &generate, Some(&mut objects));
        assert_eq!(generated.data.len(), 8 + 65);
        let private_handle = session_object_handle(&generated);
        let generated_public = p256::PublicKey::from_sec1_bytes(&generated.data[8..]).unwrap();

        let peer = p256::SecretKey::from_slice(&[0x42; 32]).unwrap();
        let peer_public = peer.public_key().to_sec1_point(false);
        let expected = diffie_hellman(peer.to_nonzero_scalar(), generated_public.as_affine());
        let expected = &expected.raw_secret_bytes()[16..];
        let mut tail = vec![0];
        tail.extend_from_slice(&private_handle.to_be_bytes());
        tail.extend_from_slice(&(peer_public.as_bytes().len() as u16).to_be_bytes());
        tail.extend_from_slice(peer_public.as_bytes());
        let derive = session_derive_request(
            SessionObjectCommand::DeriveEcdh as u8,
            FLAG_READABLE | FLAG_DERIVE,
            SessionObjectKind::GenericSecret,
            16,
            &tail,
        );
        let derived = device.execute_inner_with_session(authorization, &derive, Some(&mut objects));
        let secret_handle = session_object_handle(&derived);
        assert_eq!(
            read_session_object(&mut device, authorization, &mut objects, secret_handle).data,
            expected
        );

        let mut other_session = SessionObjects::default();
        assert_eq!(
            read_session_object(
                &mut device,
                authorization,
                &mut other_session,
                secret_handle,
            ),
            Frame::error(DeviceError::ObjectNotFound)
        );

        let protected = session_derive_request(
            SessionObjectCommand::ConcatenateData as u8,
            FLAG_DERIVE,
            SessionObjectKind::GenericSecret,
            16,
            &[secret_handle.to_be_bytes().as_slice(), b"ignored"].concat(),
        );
        let protected =
            device.execute_inner_with_session(authorization, &protected, Some(&mut objects));
        let protected_handle = session_object_handle(&protected);
        assert_eq!(objects.len(), 3);
        assert_eq!(
            read_session_object(&mut device, authorization, &mut objects, protected_handle,),
            Frame::error(DeviceError::InsufficientPermissions)
        );

        let delete = Frame::new(
            CommandCode::SessionObject as u8,
            [
                &[SessionObjectCommand::DeleteObject as u8],
                secret_handle.to_be_bytes().as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        assert!(
            device
                .execute_inner_with_session(authorization, &delete, Some(&mut objects))
                .data
                .is_empty()
        );
        assert_eq!(
            read_session_object(&mut device, authorization, &mut objects, secret_handle),
            Frame::error(DeviceError::ObjectNotFound)
        );
        assert_eq!(objects.len(), 2);
    }

    #[test]
    #[cfg(any(
        feature = "firmware-secure-channel",
        feature = "firmware-full",
        feature = "test-firmware-session-objects"
    ))]
    fn volatile_counter_kdf_and_cmac_verify_enforce_native_policy() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let authorization = device.session_authorization(1).unwrap();
        let aes = [0x5a; 16];
        let capabilities = CapabilitySet::from_capabilities([Capability::EncryptEcb]);
        assert_eq!(
            device
                .execute_inner(
                    authorization,
                    &put_symmetric_key_request(40, 1, capabilities, Algorithm::Aes128, &aes),
                )
                .data,
            40_u16.to_be_bytes()
        );

        let mut tail = vec![2];
        tail.extend_from_slice(&40_u16.to_be_bytes());
        tail.push(3);
        tail.extend_from_slice(&[1, 8, 0]);
        tail.extend_from_slice(&[0, 0, 3]);
        tail.extend_from_slice(b"SCP");
        tail.extend_from_slice(&[2, 16, 0, 0]);
        let derive = session_derive_request(
            SessionObjectCommand::CounterKdf as u8,
            FLAG_READABLE | FLAG_VERIFY,
            SessionObjectKind::Aes,
            16,
            &tail,
        );
        let mut objects = SessionObjects::default();
        let response =
            device.execute_inner_with_session(authorization, &derive, Some(&mut objects));
        let handle = session_object_handle(&response);

        let fields = [
            CounterKdfField::Counter(IntegerFormat {
                width_bits: 8,
                little_endian: false,
            }),
            CounterKdfField::Bytes(b"SCP"),
            CounterKdfField::Length(
                IntegerFormat {
                    width_bits: 16,
                    little_endian: false,
                },
                LengthMethod::Key,
            ),
        ];
        let expected = cmac_counter_kdf(&aes, &fields, 16).unwrap();
        assert_eq!(
            read_session_object(&mut device, authorization, &mut objects, handle).data,
            expected.as_slice()
        );

        let message = b"receipt input";
        let signature = cmac(&expected, message).unwrap();
        let mut verify_data = handle.to_be_bytes().to_vec();
        verify_data.push(8);
        verify_data.extend_from_slice(&signature[..8]);
        verify_data.extend_from_slice(message);
        verify_data.insert(0, SessionObjectCommand::VerifyCmac as u8);
        let verify = Frame::new(CommandCode::SessionObject as u8, verify_data).unwrap();
        assert_eq!(
            device
                .execute_inner_with_session(authorization, &verify, Some(&mut objects))
                .data,
            [1]
        );

        let insufficient = SessionAuthorization {
            authentication_key_id: 2,
            capabilities: CapabilitySet::NONE,
            delegated_capabilities: CapabilitySet::NONE,
            domains: 1,
        };
        assert_eq!(
            device.execute_inner_with_session(insufficient, &derive, Some(&mut objects)),
            Frame::error(DeviceError::InsufficientPermissions)
        );
    }

    #[test]
    fn factory_key_matches_yubihsm_superuser_semantics() {
        let device = Device::factory_default(DeviceConfig::default());
        let auth = device.session_authorization(1).unwrap();
        assert_eq!(auth.capabilities, CapabilitySet::ALL);
        assert_eq!(auth.delegated_capabilities, CapabilitySet::ALL);
        assert_eq!(auth.domains, u16::MAX);
        let material = device.authentication_key_material(1).unwrap();
        let AuthenticationKeyMaterial::Symmetric(keys) = material else {
            panic!("factory key is not symmetric")
        };
        assert_eq!(
            keys,
            &[
                0x09, 0x0b, 0x47, 0xdb, 0xed, 0x59, 0x56, 0x54, 0x90, 0x1d, 0xee, 0x1c, 0xc6, 0x55,
                0xe4, 0x20, 0x59, 0x2f, 0xd4, 0x83, 0xf7, 0x59, 0xe2, 0x99, 0x09, 0xa0, 0x4c, 0x45,
                0x05, 0xd2, 0xce, 0x0a,
            ]
        );
    }

    #[test]
    fn compiled_firmware_profile_advertises_only_enabled_algorithms_and_commands() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let authorization = device.session_authorization(1).unwrap();
        let firmware = FirmwareProfile::compiled();
        let info = device
            .execute_plain(&Frame::new(CommandCode::GetDeviceInfo as u8, Vec::new()).unwrap());
        let algorithms = &info.data[9..];
        for algorithm in [Algorithm::X25519, Algorithm::X448, Algorithm::Ed448] {
            assert_eq!(
                algorithms.contains(&(algorithm as u8)),
                firmware.extended_curves()
            );
        }
        for algorithm in [
            Algorithm::MlDsa44,
            Algorithm::MlDsa65,
            Algorithm::MlDsa87,
            Algorithm::MlKem512,
            Algorithm::MlKem768,
            Algorithm::MlKem1024,
        ] {
            assert_eq!(
                algorithms.contains(&(algorithm as u8)),
                firmware.post_quantum()
            );
        }

        let command_options = device.execute_inner(
            authorization,
            &Frame::new(CommandCode::GetOption as u8, vec![OPTION_COMMAND_AUDIT]).unwrap(),
        );
        let commands = command_options
            .data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| pair[0])
            .collect::<Vec<_>>();
        for (command, enabled) in [
            (CommandCode::DeriveEcdhKdf, firmware.prefixed_ecdh()),
            (CommandCode::SessionObject, firmware.session_objects()),
            (CommandCode::SignMlDsa, firmware.post_quantum()),
            (CommandCode::EncapsulateMlKem, firmware.post_quantum()),
            (CommandCode::DecapsulateMlKem, firmware.post_quantum()),
        ] {
            assert_eq!(commands.contains(&(command as u8)), enabled);
        }

        let authkey_info = device.execute_inner(
            authorization,
            &Frame::new(
                CommandCode::GetObjectInfo as u8,
                vec![0, 1, ObjectType::AuthenticationKey as u8],
            )
            .unwrap(),
        );
        let capabilities = CapabilitySet::from_bytes(authkey_info.data[..8].try_into().unwrap());
        for (capability, enabled) in [
            (Capability::DeriveEcdhKdf, firmware.prefixed_ecdh()),
            (Capability::SessionObjects, firmware.session_objects()),
            (Capability::SignMlDsa, firmware.post_quantum()),
            (Capability::EncapsulateMlKem, firmware.post_quantum()),
            (Capability::DecapsulateMlKem, firmware.post_quantum()),
        ] {
            assert_eq!(capabilities.contains(capability), enabled);
        }

        let algorithm_options = device.execute_inner(
            authorization,
            &Frame::new(CommandCode::GetOption as u8, vec![OPTION_ALGORITHM_TOGGLE]).unwrap(),
        );
        let option_algorithms = algorithm_options
            .data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| pair[0])
            .collect::<Vec<_>>();
        assert_eq!(option_algorithms, algorithms);
    }

    #[test]
    fn storage_info_reports_no_free_object_slots_above_nominal_capacity() {
        let mut device = Device::factory_default(DeviceConfig::default());
        for id in 1..=MAX_OBJECTS as u16 {
            device
                .provision_object(ObjectRecord {
                    info: ObjectInfo {
                        capabilities: CapabilitySet::NONE,
                        id,
                        length: 1,
                        domains: 1,
                        object_type: ObjectType::Opaque,
                        algorithm: OPAQUE_DATA_ALGORITHM,
                        sequence: 0,
                        origin: 2,
                        label: Vec::new(),
                        delegated_capabilities: CapabilitySet::NONE,
                    },
                    material: ObjectMaterial::Opaque(vec![0]),
                })
                .unwrap();
        }
        assert_eq!(device.objects.len(), MAX_OBJECTS + 1);

        let response = device.execute_inner(
            device.session_authorization(1).unwrap(),
            &Frame::new(CommandCode::GetStorageInfo as u8, []).unwrap(),
        );
        assert_eq!(&response.data[..4], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn oversized_command_result_becomes_wrong_length_before_session_encryption() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let authorization = device.session_authorization(1).unwrap();
        let maximum =
            Frame::new(CommandCode::GetPseudoRandom as u8, 8_172_u16.to_be_bytes()).unwrap();
        assert_eq!(
            device.execute_inner(authorization, &maximum).data.len(),
            8_172
        );

        let oversized =
            Frame::new(CommandCode::GetPseudoRandom as u8, 8_173_u16.to_be_bytes()).unwrap();
        assert_eq!(
            device.execute_inner(authorization, &oversized),
            Frame::error(DeviceError::WrongLength)
        );
    }

    #[test]
    fn overlong_encoded_request_is_rejected_before_dispatch() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let mut request = Frame::new(
            CommandCode::Echo as u8,
            vec![0; crate::frame::MAX_DATA_LENGTH],
        )
        .unwrap()
        .encode();
        request.push(0);

        assert_eq!(
            device.handle_encoded(&request),
            Frame::error(DeviceError::WrongLength).encode()
        );
    }

    #[test]
    fn trusted_provisioning_preserves_and_seeds_an_explicit_sequence() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let capabilities = CapabilitySet::from_capabilities([Capability::PutOpaque]);
        let key = ObjectKey {
            object_type: ObjectType::Opaque,
            id: 31,
        };
        device
            .provision_object(ObjectRecord {
                info: ObjectInfo {
                    capabilities,
                    id: key.id,
                    length: 7,
                    domains: 1,
                    object_type: key.object_type,
                    algorithm: OPAQUE_DATA_ALGORITHM,
                    sequence: 73,
                    origin: 2,
                    label: b"state".to_vec(),
                    delegated_capabilities: CapabilitySet::NONE,
                },
                material: ObjectMaterial::Opaque(b"fixture".to_vec()),
            })
            .unwrap();
        assert_eq!(device.object(key).unwrap().info.sequence, 73);
        assert_eq!(device.sequence_history.generation(key.id), Some(73));

        let admin = device.session_authorization(1).unwrap();
        assert_eq!(
            device
                .execute_inner(
                    admin,
                    &put_opaque_request_with_payload(key.id, 1, capabilities, b"runtime"),
                )
                .data,
            key.id.to_be_bytes()
        );
        assert_eq!(device.object(key).unwrap().info.sequence, 74);
    }

    #[test]
    fn opaque_read_requires_get_opaque_on_session_and_matching_domain() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let object_caps = CapabilitySet::from_capabilities([Capability::GetOpaque]);
        let response = device.execute_inner(admin, &put_opaque_request(12, 2, object_caps));
        assert_eq!(response.data, 12_u16.to_be_bytes());

        let get = Frame::new(CommandCode::GetOpaque as u8, 12_u16.to_be_bytes()).unwrap();
        assert_eq!(device.execute_inner(admin, &get).data, b"payload");

        let without_get_opaque = SessionAuthorization {
            authentication_key_id: 2,
            capabilities: CapabilitySet::NONE,
            delegated_capabilities: CapabilitySet::NONE,
            domains: 2,
        };
        assert_eq!(
            device.execute_inner(without_get_opaque, &get),
            Frame::error(DeviceError::InsufficientPermissions)
        );

        let with_get_opaque = SessionAuthorization {
            capabilities: CapabilitySet::from_capabilities([Capability::GetOpaque]),
            ..without_get_opaque
        };
        assert_eq!(device.execute_inner(with_get_opaque, &get).data, b"payload");

        let response = device.execute_inner(admin, &put_opaque_request(13, 2, CapabilitySet::NONE));
        assert_eq!(response.data, 13_u16.to_be_bytes());
        let get_without_object_capability =
            Frame::new(CommandCode::GetOpaque as u8, 13_u16.to_be_bytes()).unwrap();
        assert_eq!(
            device
                .execute_inner(with_get_opaque, &get_without_object_capability)
                .data,
            b"payload"
        );

        let info = Frame::new(
            CommandCode::GetObjectInfo as u8,
            [12_u16.to_be_bytes().as_slice(), &[ObjectType::Opaque as u8]].concat(),
        )
        .unwrap();
        assert_eq!(device.execute_inner(admin, &info).data.len(), 66);
    }

    #[test]
    fn put_opaque_updates_payload_in_place_under_existing_object_policy() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let capabilities =
            CapabilitySet::from_capabilities([Capability::GetOpaque, Capability::PutOpaque]);
        assert_eq!(
            device
                .execute_inner(
                    admin,
                    &put_opaque_request_with_payload(15, 3, capabilities, b"before"),
                )
                .data,
            15_u16.to_be_bytes()
        );
        let before = device
            .object(ObjectKey {
                object_type: ObjectType::Opaque,
                id: 15,
            })
            .unwrap()
            .info
            .clone();

        assert_eq!(
            device
                .execute_inner(
                    admin,
                    &put_opaque_request_with_payload(15, 3, capabilities, b"after update"),
                )
                .data,
            15_u16.to_be_bytes()
        );
        let updated = device
            .object(ObjectKey {
                object_type: ObjectType::Opaque,
                id: 15,
            })
            .unwrap();
        assert_eq!(
            updated.material,
            ObjectMaterial::Opaque(b"after update".to_vec())
        );
        assert_eq!(updated.info.id, before.id);
        assert_eq!(updated.info.domains, before.domains);
        assert_eq!(updated.info.capabilities, before.capabilities);
        assert_eq!(updated.info.label, before.label);
        assert_eq!(updated.info.algorithm, before.algorithm);
        assert_eq!(updated.info.sequence, before.sequence.wrapping_add(1));
        assert_eq!(updated.info.origin, before.origin);

        let mismatched =
            put_opaque_request_with_payload(15, 1, capabilities, b"must not replace the payload");
        assert_eq!(
            device.execute_inner(admin, &mismatched),
            Frame::error(DeviceError::InvalidData)
        );
        assert_eq!(
            device
                .object(ObjectKey {
                    object_type: ObjectType::Opaque,
                    id: 15,
                })
                .unwrap()
                .material,
            ObjectMaterial::Opaque(b"after update".to_vec())
        );
        assert_eq!(
            device
                .object(ObjectKey {
                    object_type: ObjectType::Opaque,
                    id: 15,
                })
                .unwrap()
                .info
                .sequence,
            before.sequence.wrapping_add(1)
        );
    }

    #[test]
    fn object_generations_are_global_by_id_and_survive_deletion_and_persistence() {
        let config = DeviceConfig::default();
        let mut device = Device::factory_default(config.clone());
        let admin = device.session_authorization(1).unwrap();
        let capabilities = CapabilitySet::from_capabilities([
            Capability::GetOpaque,
            Capability::PutOpaque,
            Capability::DeleteOpaque,
        ]);
        let key = ObjectKey {
            object_type: ObjectType::Opaque,
            id: 18,
        };
        let other_key = ObjectKey {
            object_type: ObjectType::Opaque,
            id: 19,
        };
        let symmetric_key = ObjectKey {
            object_type: ObjectType::SymmetricKey,
            id: 18,
        };

        assert_eq!(
            device
                .execute_inner(admin, &put_opaque_request(18, 1, capabilities))
                .data,
            18_u16.to_be_bytes()
        );
        assert_eq!(device.object(key).unwrap().info.sequence, 0);
        assert_eq!(
            device
                .execute_inner(
                    admin,
                    &put_symmetric_key_request(
                        18,
                        1,
                        CapabilitySet::NONE,
                        Algorithm::Aes128,
                        &[0x18; 16],
                    ),
                )
                .data,
            18_u16.to_be_bytes()
        );
        assert_eq!(device.object(symmetric_key).unwrap().info.sequence, 1);
        assert_eq!(
            device
                .execute_inner(admin, &put_opaque_request(19, 1, capabilities))
                .data,
            19_u16.to_be_bytes()
        );
        assert_eq!(device.object(other_key).unwrap().info.sequence, 0);

        let delete = Frame::new(
            CommandCode::DeleteObject as u8,
            [18_u16.to_be_bytes().as_slice(), &[ObjectType::Opaque as u8]].concat(),
        )
        .unwrap();
        assert!(device.execute_inner(admin, &delete).data.is_empty());
        let encoded = device.persistent_state().unwrap();

        let mut restored = Device::from_persistent_state(config, &encoded).unwrap();
        let restored_admin = restored.session_authorization(1).unwrap();
        assert_eq!(
            restored
                .execute_inner(restored_admin, &put_opaque_request(18, 1, capabilities))
                .data,
            18_u16.to_be_bytes()
        );
        assert_eq!(restored.object(key).unwrap().info.sequence, 2);
        assert_eq!(restored.object(symmetric_key).unwrap().info.sequence, 1);

        restored.sequence_history.record(key.id, 255);
        assert_eq!(
            restored
                .execute_inner(
                    restored_admin,
                    &put_opaque_request_with_payload(18, 1, capabilities, b"wrapped"),
                )
                .data,
            18_u16.to_be_bytes()
        );
        assert_eq!(restored.sequence_history.generation(key.id), Some(256));
        assert_eq!(restored.object(key).unwrap().info.sequence, 0);
    }

    #[test]
    fn automatic_object_ids_are_random_valid_and_globally_unused() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let opaque_response =
            device.execute_inner(admin, &put_opaque_request(0, 1, CapabilitySet::NONE));
        let opaque_id = u16::from_be_bytes(opaque_response.data.try_into().unwrap());
        assert_ne!(opaque_id, 0);
        assert_ne!(opaque_id, u16::MAX);

        let symmetric_response = device.execute_inner(
            admin,
            &put_symmetric_key_request(0, 1, CapabilitySet::NONE, Algorithm::Aes128, &[0x42; 16]),
        );
        let symmetric_id = u16::from_be_bytes(symmetric_response.data.try_into().unwrap());
        assert_ne!(symmetric_id, 0);
        assert_ne!(symmetric_id, u16::MAX);
        assert_ne!(symmetric_id, opaque_id);
        assert!(
            device
                .objects
                .keys()
                .all(|key| key.id != 0 && key.id != u16::MAX)
        );
    }

    #[test]
    fn automatic_id_sampling_rejects_reserved_and_cross_type_collisions() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        assert_eq!(
            device
                .execute_inner(
                    admin,
                    &put_symmetric_key_request(
                        7,
                        1,
                        CapabilitySet::NONE,
                        Algorithm::Aes128,
                        &[0x07; 16],
                    ),
                )
                .data,
            7_u16.to_be_bytes()
        );

        let mut candidates = [0, u16::MAX, 1, 7, 42].into_iter();
        assert_eq!(
            device
                .random_available_id_with(|| Ok(candidates.next().unwrap()))
                .unwrap(),
            42
        );
        // Explicit identifiers remain scoped by object type, as in the wire
        // protocol; only automatic allocation promises a globally unused ID.
        assert_eq!(device.resolve_id(ObjectType::Opaque, 7).unwrap(), 7);
    }

    #[test]
    fn object_generation_history_retains_every_seen_id() {
        let mut history = SequenceHistory::default();
        for id in 1..=257 {
            history.record(id, u64::from(id));
        }
        history.record(1, 999);

        assert_eq!(history.entries.len(), 257);
        assert_eq!(history.generation(1), Some(999));
        assert_eq!(history.generation(2), Some(2));
        assert_eq!(history.generation(257), Some(257));
        assert!(history.validate());
    }

    #[test]
    fn put_opaque_update_requires_put_opaque_on_session_and_object() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let get_only = CapabilitySet::from_capabilities([Capability::GetOpaque]);
        assert_eq!(
            device
                .execute_inner(admin, &put_opaque_request(16, 1, get_only))
                .data,
            16_u16.to_be_bytes()
        );
        assert_eq!(
            device.execute_inner(
                admin,
                &put_opaque_request_with_payload(16, 1, get_only, b"blocked"),
            ),
            Frame::error(DeviceError::InsufficientPermissions)
        );

        let both = CapabilitySet::from_capabilities([Capability::GetOpaque, Capability::PutOpaque]);
        assert_eq!(
            device
                .execute_inner(admin, &put_opaque_request(17, 1, both))
                .data,
            17_u16.to_be_bytes()
        );
        let without_put = SessionAuthorization {
            authentication_key_id: 2,
            capabilities: get_only,
            delegated_capabilities: CapabilitySet::NONE,
            domains: 1,
        };
        assert_eq!(
            device.execute_inner(
                without_put,
                &put_opaque_request_with_payload(17, 1, both, b"blocked"),
            ),
            Frame::error(DeviceError::InsufficientPermissions)
        );
    }

    #[test]
    fn delegated_ceiling_rejects_excess_object_capabilities_and_domains() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let restricted = SessionAuthorization {
            authentication_key_id: 2,
            capabilities: CapabilitySet::from_capabilities([Capability::PutOpaque]),
            delegated_capabilities: CapabilitySet::from_capabilities([Capability::GetOpaque]),
            domains: 0b0010,
        };
        let excessive_capability = put_opaque_request(
            12,
            0b0010,
            CapabilitySet::from_capabilities([Capability::SignEcdsa]),
        );
        assert_eq!(
            device.execute_inner(restricted, &excessive_capability),
            Frame::error(DeviceError::InsufficientPermissions)
        );
        let excessive_domain = put_opaque_request(
            12,
            0b0110,
            CapabilitySet::from_capabilities([Capability::GetOpaque]),
        );
        assert_eq!(
            device.execute_inner(restricted, &excessive_domain),
            Frame::error(DeviceError::InsufficientPermissions)
        );
    }

    #[test]
    fn creation_preserves_meaningless_capabilities_within_the_delegated_ceiling() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let put_opaque = CapabilitySet::from_capabilities([Capability::PutOpaque]);
        let authorization = SessionAuthorization {
            authentication_key_id: 2,
            capabilities: put_opaque,
            delegated_capabilities: put_opaque,
            domains: 1,
        };
        let response = device.execute_inner(authorization, &put_opaque_request(14, 1, put_opaque));
        assert_eq!(response.data, 14_u16.to_be_bytes());
        assert_eq!(
            device
                .object(ObjectKey {
                    object_type: ObjectType::Opaque,
                    id: 14,
                })
                .unwrap()
                .info
                .capabilities,
            put_opaque
        );
    }

    #[test]
    fn list_objects_hides_objects_outside_session_domains() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        device.execute_inner(
            admin,
            &put_opaque_request(
                12,
                0b0010,
                CapabilitySet::from_capabilities([Capability::GetOpaque]),
            ),
        );
        let restricted = SessionAuthorization {
            authentication_key_id: 2,
            capabilities: CapabilitySet::NONE,
            delegated_capabilities: CapabilitySet::NONE,
            domains: 0b0100,
        };
        let list = Frame::new(
            CommandCode::ListObjects as u8,
            [2, ObjectType::Opaque as u8],
        )
        .unwrap();
        assert!(device.execute_inner(restricted, &list).data.is_empty());
    }

    #[test]
    fn provisioned_authentication_key_defines_the_exact_session_context() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let capabilities = CapabilitySet::from_capabilities([
            Capability::GetPseudoRandom,
            Capability::ChangeAuthenticationKey,
        ]);
        let delegated = CapabilitySet::from_capabilities([Capability::GetOpaque]);
        let request =
            put_authentication_key_request(23, 0b0010, capabilities, delegated, &[0x55; 32]);
        assert_eq!(
            device.execute_inner(admin, &request).data,
            23_u16.to_be_bytes()
        );

        let session = device.session_authorization(23).unwrap();
        assert_eq!(session.authentication_key_id, 23);
        assert_eq!(session.capabilities, capabilities);
        assert_eq!(session.delegated_capabilities, delegated);
        assert_eq!(session.domains, 0b0010);

        let mut change = vec![0, 23, AUTHENTICATION_ALGORITHM_AES128_YUBICO];
        change.extend_from_slice(&[0x77; 32]);
        let change = Frame::new(CommandCode::ChangeAuthenticationKey as u8, change).unwrap();
        assert_eq!(
            device.execute_inner(admin, &change),
            Frame::error(DeviceError::InvalidId)
        );
        assert_eq!(
            device.execute_inner(session, &change).data,
            23_u16.to_be_bytes()
        );
        assert_eq!(
            device.authentication_key_material(23).unwrap(),
            &AuthenticationKeyMaterial::Symmetric(vec![0x77; 32])
        );
        assert_eq!(
            device
                .object(ObjectKey {
                    object_type: ObjectType::AuthenticationKey,
                    id: 23,
                })
                .unwrap()
                .info
                .sequence,
            1
        );
        // Existing sessions keep their authorization snapshot; changing the
        // key material affects only future authentication handshakes.
        assert_eq!(session.domains, 0b0010);
    }

    #[test]
    fn symmetric_handshake_and_secure_message_match_scp03_wire_semantics() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let static_keys = match device.authentication_key_material(1).unwrap() {
            AuthenticationKeyMaterial::Symmetric(keys) => keys.clone(),
            _ => unreachable!(),
        };
        let host_challenge = [0x11; CHALLENGE_LENGTH];
        let mut create_data = 1_u16.to_be_bytes().to_vec();
        create_data.extend_from_slice(&host_challenge);
        let create = Frame::new(CommandCode::CreateSession as u8, create_data).unwrap();
        let create_response = Frame::parse(&device.handle_encoded(&create.encode())).unwrap();
        assert_eq!(
            create_response.command,
            CommandCode::CreateSession as u8 | 0x80
        );
        assert_eq!(create_response.data.len(), 1 + CHALLENGE_LENGTH + 8);
        let sid = create_response.data[0];

        let mut context = [0; CHALLENGE_LENGTH * 2];
        context[..CHALLENGE_LENGTH].copy_from_slice(&host_challenge);
        context[CHALLENGE_LENGTH..].copy_from_slice(&create_response.data[1..1 + CHALLENGE_LENGTH]);
        let s_enc: [u8; BLOCK_SIZE] = scp03_kdf(&static_keys[..16], 0x04, &context, 128)
            .unwrap()
            .try_into()
            .unwrap();
        let s_mac: [u8; BLOCK_SIZE] = scp03_kdf(&static_keys[16..], 0x06, &context, 128)
            .unwrap()
            .try_into()
            .unwrap();
        let s_rmac: [u8; BLOCK_SIZE] = scp03_kdf(&static_keys[16..], 0x07, &context, 128)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            &create_response.data[1 + CHALLENGE_LENGTH..],
            scp03_kdf(&s_mac, 0x00, &context, 64).unwrap()
        );

        let mut authenticate_payload = vec![sid];
        authenticate_payload.extend_from_slice(&scp03_kdf(&s_mac, 0x01, &context, 64).unwrap());
        let mut authenticate_without_mac = vec![CommandCode::AuthenticateSession as u8, 0, 17];
        authenticate_without_mac.extend_from_slice(&authenticate_payload);
        let mut authenticate_mac_input = vec![0; BLOCK_SIZE];
        authenticate_mac_input.extend_from_slice(&authenticate_without_mac);
        let command_mac = cmac(&s_mac, &authenticate_mac_input).unwrap();
        authenticate_payload.extend_from_slice(&command_mac[..8]);
        let authenticate =
            Frame::new(CommandCode::AuthenticateSession as u8, authenticate_payload).unwrap();
        assert_eq!(
            Frame::parse(&device.handle_encoded(&authenticate.encode())).unwrap(),
            Frame::response(CommandCode::AuthenticateSession as u8, Vec::new())
        );

        let mut counter = [0; BLOCK_SIZE];
        counter[BLOCK_SIZE - 1] = 1;
        let iv = encrypt_block(&s_enc, &counter).unwrap();
        let echo_payload = b"session keepalive".to_vec();
        let inner = Frame::new(CommandCode::Echo as u8, echo_payload.clone()).unwrap();
        let ciphertext = cbc_encrypt(&s_enc, &iv, &pad(&inner.encode())).unwrap();
        let mut message_payload = vec![sid];
        message_payload.extend_from_slice(&ciphertext);
        let total_length = message_payload.len() + 8;
        let mut message_without_mac = vec![
            CommandCode::SessionMessage as u8,
            (total_length >> 8) as u8,
            total_length as u8,
        ];
        message_without_mac.extend_from_slice(&message_payload);
        let mut message_mac_input = command_mac.to_vec();
        message_mac_input.extend_from_slice(&message_without_mac);
        let message_mac = cmac(&s_mac, &message_mac_input).unwrap();
        message_payload.extend_from_slice(&message_mac[..8]);
        let message = Frame::new(CommandCode::SessionMessage as u8, message_payload).unwrap();
        let prior_activity = Instant::now().checked_sub(Duration::from_secs(15)).unwrap();
        device.sessions.get_mut(&sid).unwrap().last_activity = prior_activity;
        let response = Frame::parse(&device.handle_encoded(&message.encode())).unwrap();
        assert_eq!(response.command, CommandCode::SessionMessage as u8 | 0x80);
        assert!(device.sessions.get(&sid).unwrap().last_activity > prior_activity);

        let response_payload_length = response.data.len() - 8;
        let response_without_mac = &response.encode()[..3 + response_payload_length];
        let mut rmac_input = message_mac.to_vec();
        rmac_input.extend_from_slice(response_without_mac);
        let expected_rmac = cmac(&s_rmac, &rmac_input).unwrap();
        assert_eq!(
            &response.data[response_payload_length..],
            &expected_rmac[..8]
        );
        assert_eq!(response.data[0], sid);
        let clear = cbc_decrypt(&s_enc, &iv, &response.data[1..response_payload_length]).unwrap();
        let inner_response = Frame::parse(&unpad(clear).unwrap()).unwrap();
        assert_eq!(inner_response.command, CommandCode::Echo as u8 | 0x80);
        assert_eq!(inner_response.data, echo_payload);
        assert_eq!(device.active_session_count(), 1);

        device.sessions.get_mut(&sid).unwrap().last_activity = Instant::now()
            .checked_sub(SESSION_INACTIVITY_TIMEOUT + Duration::from_millis(1))
            .unwrap();
        assert_eq!(
            Frame::parse(&device.handle_encoded(&message.encode())).unwrap(),
            Frame::error(DeviceError::InvalidSession)
        );
        assert_eq!(device.active_session_count(), 0);
    }

    #[test]
    fn expired_sessions_are_reclaimed_before_allocating_a_new_session() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let create = |challenge: u8| {
            let mut data = 1_u16.to_be_bytes().to_vec();
            data.extend_from_slice(&[challenge; CHALLENGE_LENGTH]);
            Frame::new(CommandCode::CreateSession as u8, data).unwrap()
        };

        for expected_sid in 0..MAX_SESSIONS {
            let response =
                Frame::parse(&device.handle_encoded(&create(expected_sid).encode())).unwrap();
            assert_eq!(response.command, CommandCode::CreateSession as u8 | 0x80);
            assert_eq!(response.data[0], expected_sid);
        }
        assert_eq!(device.active_session_count(), usize::from(MAX_SESSIONS));
        assert_eq!(
            Frame::parse(&device.handle_encoded(&create(0xff).encode())).unwrap(),
            Frame::error(DeviceError::SessionsFull)
        );

        let expired_at = Instant::now()
            .checked_sub(SESSION_INACTIVITY_TIMEOUT + Duration::from_millis(1))
            .unwrap();
        for session in device.sessions.values_mut() {
            session.last_activity = expired_at;
        }
        let response = Frame::parse(&device.handle_encoded(&create(0xfe).encode())).unwrap();
        assert_eq!(response.command, CommandCode::CreateSession as u8 | 0x80);
        assert_eq!(response.data[0], 0);
        assert_eq!(device.active_session_count(), 1);
    }

    #[test]
    fn directly_available_commands_are_also_available_in_a_session() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let authorization = device.session_authorization(1).unwrap();
        for request in [
            Frame::new(CommandCode::Echo as u8, b"echo".to_vec()).unwrap(),
            Frame::new(CommandCode::GetDeviceInfo as u8, Vec::new()).unwrap(),
            Frame::new(CommandCode::GetDevicePublicKey as u8, Vec::new()).unwrap(),
        ] {
            assert_eq!(
                device.execute_inner(authorization, &request),
                device.execute_plain(&request)
            );
        }
    }

    #[test]
    fn shared_software_key_core_backs_asymmetric_generation_and_signing() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let object_capabilities =
            CapabilitySet::from_capabilities([Capability::SignEcdsa, Capability::DeriveEcdh]);
        let generate = generate_asymmetric_key_request(42, 0b0010, object_capabilities, 12);
        assert_eq!(
            device.execute_inner(admin, &generate).data,
            42_u16.to_be_bytes()
        );

        let get_public = Frame::new(CommandCode::GetPublicKey as u8, 42_u16.to_be_bytes()).unwrap();
        let public_response = device.execute_inner(admin, &get_public);
        assert_eq!(
            public_response.command,
            CommandCode::GetPublicKey as u8 | 0x80
        );
        assert_eq!(public_response.data[0], 12);
        let public = SoftwarePublicKey::Ec {
            curve: EcCurve::P256,
            uncompressed: [vec![0x04], public_response.data[1..].to_vec()].concat(),
        };

        let digest = software_key_core::digest::HashAlgorithm::Sha256
            .digest(b"protocol-neutral key implementation");
        let sign = Frame::new(
            CommandCode::SignEcdsa as u8,
            [42_u16.to_be_bytes().as_slice(), digest.as_slice()].concat(),
        )
        .unwrap();
        let signature = device.execute_inner(admin, &sign);
        assert_eq!(signature.data.first(), Some(&0x30));
        let raw_signature =
            software_key_core::software_signing::ecdsa_signature_from_der(&signature.data, 32)
                .unwrap();
        public
            .verify_prehash(SignatureScheme::EcdsaP256Sha256, &digest, &raw_signature)
            .unwrap();

        let wrong_domain = SessionAuthorization {
            authentication_key_id: 9,
            capabilities: CapabilitySet::from_capabilities([Capability::SignEcdsa]),
            delegated_capabilities: CapabilitySet::NONE,
            domains: 0b0100,
        };
        assert_eq!(
            device.execute_inner(wrong_domain, &sign),
            Frame::error(DeviceError::ObjectNotFound)
        );
    }

    #[test]
    #[cfg(feature = "firmware-full")]
    fn post_quantum_commands_sign_encapsulate_and_survive_persistence() {
        use software_key_core::post_quantum::{MlDsaParameterSet, verify_ml_dsa};

        const DSA_ID: u16 = 70;
        const KEM_ID: u16 = 71;
        let config = DeviceConfig::default();
        let mut device = Device::factory_default(config.clone());
        let admin = device.session_authorization(1).unwrap();

        let generate_dsa = generate_asymmetric_key_request(
            DSA_ID,
            1,
            CapabilitySet::from_capabilities([Capability::SignMlDsa]),
            Algorithm::MlDsa87 as u8,
        );
        assert_eq!(
            device.execute_inner(admin, &generate_dsa).data,
            DSA_ID.to_be_bytes()
        );
        let generate_kem = generate_asymmetric_key_request(
            KEM_ID,
            1,
            CapabilitySet::from_capabilities([
                Capability::EncapsulateMlKem,
                Capability::DecapsulateMlKem,
            ]),
            Algorithm::MlKem1024 as u8,
        );
        assert_eq!(
            device.execute_inner(admin, &generate_kem).data,
            KEM_ID.to_be_bytes()
        );

        let public_dsa = device.execute_inner(
            admin,
            &Frame::new(CommandCode::GetPublicKey as u8, DSA_ID.to_be_bytes()).unwrap(),
        );
        assert_eq!(public_dsa.data[0], Algorithm::MlDsa87 as u8);
        let context = b"virtual-yubihsm";
        let message = b"signature larger than the former transport ceiling";
        let sign_data = [
            DSA_ID.to_be_bytes().as_slice(),
            &[0, context.len() as u8],
            context,
            message,
        ]
        .concat();
        let sign = Frame::new(CommandCode::SignMlDsa as u8, sign_data.clone()).unwrap();
        let signature = device.execute_inner(admin, &sign);
        assert_eq!(signature.command, CommandCode::SignMlDsa as u8 | 0x80);
        assert!(signature.data.len() > 3_136);
        verify_ml_dsa(
            MlDsaParameterSet::MlDsa87,
            &public_dsa.data[1..],
            message,
            context,
            &signature.data,
        )
        .unwrap();

        let encapsulate = Frame::new(
            CommandCode::EncapsulateMlKem as u8,
            KEM_ID.to_be_bytes().to_vec(),
        )
        .unwrap();
        let encapsulated = device.execute_inner(admin, &encapsulate);
        assert_eq!(
            encapsulated.command,
            CommandCode::EncapsulateMlKem as u8 | 0x80
        );
        assert_eq!(encapsulated.data.len(), 1_568 + 32);
        let (ciphertext, shared) = encapsulated.data.split_at(1_568);
        let decapsulate = Frame::new(
            CommandCode::DecapsulateMlKem as u8,
            [KEM_ID.to_be_bytes().as_slice(), ciphertext].concat(),
        )
        .unwrap();
        assert_eq!(device.execute_inner(admin, &decapsulate).data, shared);

        for (command, malformed) in [
            (CommandCode::EncapsulateMlKem, vec![]),
            (CommandCode::EncapsulateMlKem, vec![0, KEM_ID as u8, 0]),
            (CommandCode::DecapsulateMlKem, vec![]),
            (CommandCode::DecapsulateMlKem, vec![0, KEM_ID as u8]),
            (CommandCode::DecapsulateMlKem, vec![0, KEM_ID as u8, 1]),
        ] {
            let response =
                device.execute_inner(admin, &Frame::new(command as u8, malformed).unwrap());
            assert!(matches!(
                DeviceError::from_byte(response.data[0]),
                Some(DeviceError::WrongLength | DeviceError::InvalidData)
            ));
        }
        let restricted = SessionAuthorization {
            authentication_key_id: 2,
            capabilities: CapabilitySet::NONE,
            delegated_capabilities: CapabilitySet::NONE,
            domains: 1,
        };
        assert_eq!(
            device.execute_inner(restricted, &sign),
            Frame::error(DeviceError::InsufficientPermissions)
        );

        let state = device.persistent_state().unwrap();
        let mut restored = Device::from_persistent_state(config, &state).unwrap();
        assert_eq!(restored.execute_inner(admin, &decapsulate).data, shared);
        let restored_signature = restored.execute_inner(admin, &sign);
        verify_ml_dsa(
            MlDsaParameterSet::MlDsa87,
            &public_dsa.data[1..],
            message,
            context,
            &restored_signature.data,
        )
        .unwrap();
    }

    #[test]
    #[cfg(feature = "firmware-full")]
    fn post_quantum_seed_imports_use_existing_asymmetric_object_commands() {
        use software_key_core::post_quantum::{MlDsaParameterSet, verify_ml_dsa};

        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let dsa_capabilities = CapabilitySet::from_capabilities([Capability::SignMlDsa]);
        let kem_capabilities = CapabilitySet::from_capabilities([
            Capability::EncapsulateMlKem,
            Capability::DecapsulateMlKem,
        ]);

        let put_dsa =
            put_asymmetric_key_request(72, 1, dsa_capabilities, Algorithm::MlDsa44, &[0x44; 32]);
        assert_eq!(
            device.execute_inner(admin, &put_dsa).data,
            72_u16.to_be_bytes()
        );
        let put_kem =
            put_asymmetric_key_request(73, 1, kem_capabilities, Algorithm::MlKem512, &[0x51; 64]);
        assert_eq!(
            device.execute_inner(admin, &put_kem).data,
            73_u16.to_be_bytes()
        );

        let public = device.execute_inner(
            admin,
            &Frame::new(CommandCode::GetPublicKey as u8, 72_u16.to_be_bytes()).unwrap(),
        );
        assert_eq!(public.data.len(), 1 + 1_312);
        let sign = Frame::new(
            CommandCode::SignMlDsa as u8,
            [72_u16.to_be_bytes().as_slice(), &[0, 0], b"seed import"].concat(),
        )
        .unwrap();
        let signature = device.execute_inner(admin, &sign).data;
        verify_ml_dsa(
            MlDsaParameterSet::MlDsa44,
            &public.data[1..],
            b"seed import",
            &[],
            &signature,
        )
        .unwrap();

        for (algorithm, seed) in [
            (Algorithm::MlDsa44, vec![0; 31]),
            (Algorithm::MlKem512, vec![0; 63]),
        ] {
            let request = put_asymmetric_key_request(74, 1, CapabilitySet::NONE, algorithm, &seed);
            assert_eq!(
                device.execute_inner(admin, &request),
                Frame::error(DeviceError::WrongLength)
            );
        }
    }

    #[test]
    fn asymmetric_authentication_key_exposes_its_public_key() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let host_static = p256::SecretKey::from_slice(&[1; 32]).unwrap();
        let host_public = host_static.public_key().to_sec1_point(false);
        let raw_public = &host_public.as_bytes()[1..];
        let put = put_asymmetric_authentication_key_request(
            44,
            1,
            CapabilitySet::NONE,
            CapabilitySet::NONE,
            raw_public,
        );
        assert_eq!(device.execute_inner(admin, &put).data, 44_u16.to_be_bytes());

        let get_public = Frame::new(
            CommandCode::GetPublicKey as u8,
            [
                44_u16.to_be_bytes().as_slice(),
                &[ObjectType::AuthenticationKey as u8],
            ]
            .concat(),
        )
        .unwrap();
        let response = device.execute_inner(admin, &get_public);
        assert_eq!(response.command, CommandCode::GetPublicKey as u8 | 0x80);
        assert_eq!(response.data[0], AUTHENTICATION_ALGORITHM_EC_P256);
        assert_eq!(&response.data[1..], raw_public);
    }

    #[test]
    fn rsa_generation_and_pkcs1_signing_use_the_official_wire_format() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let capabilities = CapabilitySet::from_capabilities([
            Capability::SignPkcs,
            Capability::SignPss,
            Capability::DecryptPkcs,
            Capability::DecryptOaep,
        ]);
        let generate =
            generate_asymmetric_key_request(43, 1, capabilities, Algorithm::Rsa2048 as u8);
        assert_eq!(
            device.execute_inner(admin, &generate).data,
            43_u16.to_be_bytes()
        );
        assert_eq!(
            device
                .object(ObjectKey {
                    object_type: ObjectType::AsymmetricKey,
                    id: 43,
                })
                .unwrap()
                .info
                .length,
            896
        );

        let get_public = Frame::new(CommandCode::GetPublicKey as u8, 43_u16.to_be_bytes()).unwrap();
        let public_response = device.execute_inner(admin, &get_public);
        assert_eq!(public_response.data[0], Algorithm::Rsa2048 as u8);
        assert_eq!(public_response.data.len(), 257);
        let public = SoftwarePublicKey::Rsa {
            modulus: public_response.data[1..].to_vec(),
            exponent: vec![1, 0, 1],
        };
        let digest =
            software_key_core::digest::HashAlgorithm::Sha256.digest(b"virtual YubiHSM RSA command");
        let sign = Frame::new(
            CommandCode::SignPkcs1 as u8,
            [43_u16.to_be_bytes().as_slice(), digest.as_slice()].concat(),
        )
        .unwrap();
        let signature = device.execute_inner(admin, &sign);
        assert_eq!(signature.data.len(), 256);
        public
            .verify_prehash(SignatureScheme::RsaPkcs1Sha256, &digest, &signature.data)
            .unwrap();

        // The official command infers SHA-1/SHA-2 from raw digest lengths.
        // Hashes with colliding lengths, such as SHA3-256, remain unambiguous
        // when the caller supplies the complete DigestInfo payload.
        let sha3_digest = RsaHashAlgorithm::Sha3_256.digest(b"encoded SHA3 DigestInfo");
        let sha3_digest_info =
            software_key_core::rsa_signing::digest_info(RsaHashAlgorithm::Sha3_256, &sha3_digest)
                .unwrap();
        let sign_encoded = Frame::new(
            CommandCode::SignPkcs1 as u8,
            [43_u16.to_be_bytes().as_slice(), sha3_digest_info.as_slice()].concat(),
        )
        .unwrap();
        let encoded_signature = device.execute_inner(admin, &sign_encoded).data;
        let rsa_public = RsaPublicKey::new(
            BigUint::from_bytes_be(&public_response.data[1..]),
            BigUint::from(65_537_u32),
        )
        .unwrap();
        software_key_core::rsa_signing::rsa_verify_pkcs1v15_payload(
            &rsa_public,
            &sha3_digest_info,
            &encoded_signature,
        )
        .unwrap();

        let plaintext = b"RSA decryption command";
        let ciphertext = public.encrypt_rsa_pkcs1v15(plaintext).unwrap();
        let decrypt = Frame::new(
            CommandCode::DecryptPkcs1 as u8,
            [43_u16.to_be_bytes().as_slice(), ciphertext.as_slice()].concat(),
        )
        .unwrap();
        assert_eq!(device.execute_inner(admin, &decrypt).data, plaintext);

        let label_digest = RsaHashAlgorithm::Sha256.digest(b"OAEP label");
        let ciphertext = public
            .encrypt_rsa_oaep_digest(plaintext, &label_digest, RsaHashAlgorithm::Sha384)
            .unwrap();
        let decrypt = Frame::new(
            CommandCode::DecryptOaep as u8,
            [
                43_u16.to_be_bytes().as_slice(),
                &[Algorithm::Mgf1Sha384 as u8],
                ciphertext.as_slice(),
                label_digest.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        assert_eq!(device.execute_inner(admin, &decrypt).data, plaintext);
    }

    #[test]
    #[cfg(feature = "firmware-full")]
    fn direct_pkcs1_variant_wraps_and_imports_symmetric_key_material() {
        const WRAP_ID: u16 = 200;
        const SOURCE_ID: u16 = 201;
        const IMPORTED_ID: u16 = 202;
        const SECRET: [u8; 16] = [0x5a; 16];

        fn record(
            id: u16,
            object_type: ObjectType,
            algorithm: Algorithm,
            capabilities: CapabilitySet,
            delegated_capabilities: CapabilitySet,
            material: ObjectMaterial,
        ) -> ObjectRecord {
            let mut record = ObjectRecord {
                info: ObjectInfo {
                    capabilities,
                    id,
                    length: 0,
                    domains: 1,
                    object_type,
                    algorithm: algorithm as u8,
                    sequence: 0,
                    origin: 2,
                    label: Vec::new(),
                    delegated_capabilities,
                },
                material,
            };
            record.normalize_info_length().unwrap();
            record
        }

        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let private = asymmetric_key_material(Algorithm::Rsa2048, true, &[]).unwrap();
        let ObjectMaterial::SigningKey(signing) = &private else {
            panic!("generated RSA wrap key has the wrong material type");
        };
        let SoftwarePublicKey::Rsa { modulus, .. } = signing.public_key() else {
            panic!("generated RSA wrap key has the wrong public-key type");
        };
        device
            .provision_object(record(
                WRAP_ID,
                ObjectType::WrapKey,
                Algorithm::Rsa2048,
                CapabilitySet::from_capabilities([Capability::ImportWrapped]),
                CapabilitySet::NONE,
                private,
            ))
            .unwrap();
        device
            .provision_object(record(
                WRAP_ID,
                ObjectType::PublicWrapKey,
                Algorithm::Rsa2048,
                CapabilitySet::from_capabilities([Capability::ExportWrapped]),
                CapabilitySet::from_capabilities([Capability::ExportableUnderWrap]),
                ObjectMaterial::Public(modulus),
            ))
            .unwrap();
        device
            .provision_object(record(
                SOURCE_ID,
                ObjectType::SymmetricKey,
                Algorithm::Aes128,
                CapabilitySet::from_capabilities([Capability::ExportableUnderWrap]),
                CapabilitySet::NONE,
                ObjectMaterial::Secret(SECRET.to_vec()),
            ))
            .unwrap();

        let get = Frame::new(
            CommandCode::GetRsaWrappedKey as u8,
            [
                WRAP_ID.to_be_bytes().as_slice(),
                &[ObjectType::SymmetricKey as u8],
                SOURCE_ID.to_be_bytes().as_slice(),
                &[0, 0, 0],
            ]
            .concat(),
        )
        .unwrap();
        let wrapped = device.execute_inner(admin, &get);
        assert_eq!(wrapped.command, CommandCode::GetRsaWrappedKey as u8 | 0x80);
        assert_eq!(wrapped.data.len(), 256);
        assert_eq!(
            signing_key(
                device
                    .object(ObjectKey {
                        object_type: ObjectType::WrapKey,
                        id: WRAP_ID,
                    })
                    .unwrap()
            )
            .unwrap()
            .decrypt_rsa_pkcs1v15(&wrapped.data)
            .unwrap()
            .as_slice(),
            SECRET
        );

        let mut put_data = Vec::new();
        put_data.extend_from_slice(&WRAP_ID.to_be_bytes());
        put_data.push(ObjectType::SymmetricKey as u8);
        put_data.extend_from_slice(&IMPORTED_ID.to_be_bytes());
        put_data.resize(45, 0);
        put_data.extend_from_slice(&1_u16.to_be_bytes());
        put_data.extend_from_slice(&CapabilitySet::NONE.to_bytes());
        put_data.push(Algorithm::Aes128 as u8);
        put_data.extend_from_slice(&[0, 0]);
        put_data.extend_from_slice(&wrapped.data);
        let put = Frame::new(CommandCode::PutRsaWrappedKey as u8, put_data).unwrap();
        assert_eq!(
            device.execute_inner(admin, &put).data,
            [ObjectType::SymmetricKey as u8, 0, IMPORTED_ID as u8]
        );
        assert_eq!(
            device
                .object(ObjectKey {
                    object_type: ObjectType::SymmetricKey,
                    id: IMPORTED_ID,
                })
                .unwrap()
                .material,
            ObjectMaterial::Secret(SECRET.to_vec())
        );
    }

    #[test]
    fn wrapped_object_cbor_v1_round_trips_every_material_representation() {
        let ec_secret = asymmetric_key_material(Algorithm::EcP256, true, &[]).unwrap();
        let ed25519_secret = asymmetric_key_material(Algorithm::Ed25519, true, &[]).unwrap();
        let x25519_secret = asymmetric_key_material(Algorithm::X25519, true, &[]).unwrap();
        let ed448_secret = asymmetric_key_material(Algorithm::Ed448, true, &[]).unwrap();
        let x448_secret = asymmetric_key_material(Algorithm::X448, true, &[]).unwrap();
        let rsa_secret = asymmetric_key_material(Algorithm::Rsa2048, true, &[]).unwrap();
        let rsa_record =
            wrapped_test_record(109, ObjectType::WrapKey, Algorithm::Rsa2048, rsa_secret);
        let SoftwarePublicKey::Rsa { modulus, .. } = signing_key(&rsa_record).unwrap().public_key()
        else {
            panic!("generated RSA key did not have an RSA public key");
        };
        let auth_private =
            SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
        let SoftwarePublicKey::Ec {
            uncompressed: auth_public,
            ..
        } = auth_private.public_key()
        else {
            panic!("generated P-256 key did not have an EC public key");
        };

        let records = vec![
            wrapped_test_record(
                100,
                ObjectType::Opaque,
                Algorithm::OpaqueData,
                ObjectMaterial::Opaque(vec![0, 1, 2, 0xff]),
            ),
            wrapped_test_record(
                101,
                ObjectType::Template,
                Algorithm::TemplateSsh,
                ObjectMaterial::Opaque(b"template".to_vec()),
            ),
            wrapped_test_record(
                102,
                ObjectType::SymmetricKey,
                Algorithm::Aes256,
                ObjectMaterial::Secret(vec![0x22; 32]),
            ),
            wrapped_test_record(
                103,
                ObjectType::HmacKey,
                Algorithm::HmacSha384,
                ObjectMaterial::Secret(vec![0x33; 48]),
            ),
            wrapped_test_record(
                104,
                ObjectType::WrapKey,
                Algorithm::Aes192CcmWrap,
                ObjectMaterial::Secret(vec![0x44; 24]),
            ),
            wrapped_test_record(
                105,
                ObjectType::AuthenticationKey,
                Algorithm::Aes128YubicoAuthentication,
                ObjectMaterial::Authentication(AuthenticationKeyMaterial::Symmetric(vec![
                    0x55;
                    32
                ])),
            ),
            wrapped_test_record(
                106,
                ObjectType::AuthenticationKey,
                Algorithm::EcP256YubicoAuthentication,
                ObjectMaterial::Authentication(AuthenticationKeyMaterial::Asymmetric(
                    auth_public[1..].to_vec(),
                )),
            ),
            wrapped_test_record(
                107,
                ObjectType::OtpAeadKey,
                Algorithm::Aes128YubicoOtp,
                ObjectMaterial::OtpAeadKey {
                    nonce_id: [1, 2, 3, 4],
                    key: vec![0x66; 16],
                },
            ),
            wrapped_test_record(108, ObjectType::AsymmetricKey, Algorithm::EcP256, ec_secret),
            rsa_record,
            wrapped_test_record(
                110,
                ObjectType::PublicWrapKey,
                Algorithm::Rsa2048,
                ObjectMaterial::Public(modulus),
            ),
            wrapped_test_record(
                111,
                ObjectType::AsymmetricKey,
                Algorithm::Ed25519,
                ed25519_secret,
            ),
            wrapped_test_record(
                112,
                ObjectType::AsymmetricKey,
                Algorithm::X25519,
                x25519_secret,
            ),
            wrapped_test_record(
                113,
                ObjectType::AsymmetricKey,
                Algorithm::Ed448,
                ed448_secret,
            ),
            wrapped_test_record(114, ObjectType::AsymmetricKey, Algorithm::X448, x448_secret),
        ];

        for record in records {
            let encoded = encode_wrapped_object(&record).unwrap();
            let mut expected = record;
            expected.info.sequence = 0;
            expected.info.origin &= 0x0f;
            assert_eq!(decode_wrapped_object(&encoded).unwrap(), expected);
        }
    }

    #[test]
    fn wrapped_object_cbor_v1_rejects_noncanonical_and_mismatched_records() {
        let record = wrapped_test_record(
            120,
            ObjectType::Opaque,
            Algorithm::OpaqueData,
            ObjectMaterial::Opaque(b"payload".to_vec()),
        );
        let encoded = encode_wrapped_object(&record).unwrap();

        let schema_offset = encoded
            .windows(WRAPPED_OBJECT_SCHEMA.len())
            .position(|window| window == WRAPPED_OBJECT_SCHEMA.as_bytes())
            .unwrap();
        let version_offset = schema_offset + WRAPPED_OBJECT_SCHEMA.len();
        assert_eq!(encoded[version_offset], WRAPPED_OBJECT_VERSION);
        let mut noncanonical = encoded.clone();
        noncanonical.insert(version_offset, 0x18);
        assert_eq!(
            decode_wrapped_object(&noncanonical),
            Err(DeviceError::InvalidData)
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_wrapped_object(&trailing),
            Err(DeviceError::InvalidData)
        );

        let mut input = Cursor::new(&encoded);
        let mut value: CborValue = ciborium::from_reader(&mut input).unwrap();
        let CborValue::Array(fields) = &mut value else {
            panic!("wrapped object was not a CBOR array");
        };
        let CborValue::Array(material) = &mut fields[10] else {
            panic!("wrapped material was not a CBOR array");
        };
        material[0] = CborValue::Integer(WRAPPED_MATERIAL_SECRET.into());
        let mut mismatched = Vec::new();
        ciborium::into_writer(&value, &mut mismatched).unwrap();
        assert_eq!(
            decode_wrapped_object(&mismatched),
            Err(DeviceError::InvalidData)
        );
    }

    #[test]
    #[cfg(any(
        feature = "firmware-secure-channel",
        feature = "firmware-full",
        feature = "test-firmware-prefixed-ecdh"
    ))]
    fn protected_ecdh_kdf_can_authenticate_back_to_the_same_hsm() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let static_private = p256::SecretKey::from_slice(&[3; 32]).unwrap();
        let static_public = static_private.public_key().to_sec1_point(false);
        let derive_capability = CapabilitySet::from_capabilities([Capability::DeriveEcdhKdf]);
        let put_static = put_asymmetric_key_request(
            32,
            1,
            derive_capability,
            Algorithm::EcP256,
            static_private.to_bytes().as_slice(),
        );
        assert_eq!(
            device.execute_inner(admin, &put_static).data,
            32_u16.to_be_bytes()
        );

        let session_capabilities = CapabilitySet::from_capabilities([Capability::GetPseudoRandom]);
        let put_authentication = put_asymmetric_authentication_key_request(
            33,
            1,
            session_capabilities,
            CapabilitySet::NONE,
            &static_public.as_bytes()[1..],
        );
        assert_eq!(
            device.execute_inner(admin, &put_authentication).data,
            33_u16.to_be_bytes()
        );

        let host_ephemeral = p256::SecretKey::from_slice(&[4; 32]).unwrap();
        let host_ephemeral_public = host_ephemeral.public_key().to_sec1_point(false);
        let mut create_data = 33_u16.to_be_bytes().to_vec();
        create_data.extend_from_slice(host_ephemeral_public.as_bytes());
        let create = Frame::new(CommandCode::CreateSession as u8, create_data).unwrap();
        let create_response = Frame::parse(&device.handle_encoded(&create.encode())).unwrap();
        assert_eq!(
            create_response.command,
            CommandCode::CreateSession as u8 | 0x80
        );
        assert_eq!(create_response.data.len(), 1 + 65 + 16);
        let sid = create_response.data[0];

        // Zephemeral is intentionally calculated by the untrusted host. The
        // static ECDH result remains inside object 32 and enters the KDF there.
        let device_ephemeral =
            p256::PublicKey::from_sec1_bytes(&create_response.data[1..66]).unwrap();
        let ephemeral_secret = diffie_hellman(
            host_ephemeral.to_nonzero_scalar(),
            device_ephemeral.as_affine(),
        );
        let device_public_request =
            Frame::new(CommandCode::GetDevicePublicKey as u8, Vec::new()).unwrap();
        let mut device_static_public = device.execute_plain(&device_public_request).data;
        device_static_public[0] = 0x04;

        let shared_info = [0x3c, 0x88, 0x10];
        let mut derive_data = Vec::new();
        derive_data.extend_from_slice(&32_u16.to_be_bytes());
        derive_data.push(3); // X9.63 SHA-256
        derive_data.extend_from_slice(&64_u16.to_be_bytes());
        for value in [
            device_static_public.len(),
            ephemeral_secret.raw_secret_bytes().len(),
            shared_info.len(),
        ] {
            derive_data.extend_from_slice(&u16::try_from(value).unwrap().to_be_bytes());
        }
        derive_data.extend_from_slice(&device_static_public);
        derive_data.extend_from_slice(ephemeral_secret.raw_secret_bytes());
        derive_data.extend_from_slice(&shared_info);
        let derive = Frame::new(CommandCode::DeriveEcdhKdf as u8, derive_data).unwrap();
        let derive_response = device.execute_inner(admin, &derive);
        assert_eq!(
            derive_response.command,
            CommandCode::DeriveEcdhKdf as u8 | 0x80
        );
        assert_eq!(derive_response.data.len(), 64);
        let session_keys = derive_response.data;

        let mut receipt_input = create_response.data[1..66].to_vec();
        receipt_input.extend_from_slice(host_ephemeral_public.as_bytes());
        assert_eq!(
            &create_response.data[66..],
            cmac(&session_keys[..16], &receipt_input).unwrap()
        );

        let raw_derive = Frame::new(
            CommandCode::DeriveEcdh as u8,
            [
                32_u16.to_be_bytes().as_slice(),
                device_static_public.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        assert_eq!(
            device.execute_inner(admin, &raw_derive),
            Frame::error(DeviceError::InsufficientPermissions)
        );

        // Use the protected result as real SCP11 session keys. A successful
        // authorized command proves more than merely reproducing the receipt.
        let mut counter = [0; BLOCK_SIZE];
        counter[BLOCK_SIZE - 1] = 1;
        let iv = encrypt_block(&session_keys[16..32], &counter).unwrap();
        let inner = Frame::new(CommandCode::GetPseudoRandom as u8, 16_u16.to_be_bytes()).unwrap();
        let ciphertext = cbc_encrypt(&session_keys[16..32], &iv, &pad(&inner.encode())).unwrap();
        let mut message_payload = vec![sid];
        message_payload.extend_from_slice(&ciphertext);
        let total_length = message_payload.len() + 8;
        let mut message_without_mac = vec![
            CommandCode::SessionMessage as u8,
            (total_length >> 8) as u8,
            total_length as u8,
        ];
        message_without_mac.extend_from_slice(&message_payload);
        let mut message_mac_input = create_response.data[66..].to_vec();
        message_mac_input.extend_from_slice(&message_without_mac);
        let message_mac = cmac(&session_keys[32..48], &message_mac_input).unwrap();
        message_payload.extend_from_slice(&message_mac[..8]);
        let message = Frame::new(CommandCode::SessionMessage as u8, message_payload).unwrap();
        let response = Frame::parse(&device.handle_encoded(&message.encode())).unwrap();
        assert_eq!(response.command, CommandCode::SessionMessage as u8 | 0x80);

        let response_payload_length = response.data.len() - 8;
        let response_without_mac = &response.encode()[..3 + response_payload_length];
        let mut rmac_input = message_mac.to_vec();
        rmac_input.extend_from_slice(response_without_mac);
        let expected_rmac = cmac(&session_keys[48..64], &rmac_input).unwrap();
        assert_eq!(
            &response.data[response_payload_length..],
            &expected_rmac[..8]
        );
        assert_eq!(response.data[0], sid);
        let clear = cbc_decrypt(
            &session_keys[16..32],
            &iv,
            &response.data[1..response_payload_length],
        )
        .unwrap();
        let inner_response = Frame::parse(&unpad(clear).unwrap()).unwrap();
        assert_eq!(
            inner_response.command,
            CommandCode::GetPseudoRandom as u8 | 0x80
        );
        assert_eq!(inner_response.data.len(), 16);
    }

    #[test]
    fn persistent_state_round_trips_objects_options_audit_and_device_identity() {
        let config = DeviceConfig {
            serial: 77,
            ..DeviceConfig::default()
        };
        let mut device =
            Device::factory_default_with_device_static_private(config.clone(), [7; 32]).unwrap();
        let admin = device.session_authorization(1).unwrap();
        let put = put_opaque_request(
            42,
            1,
            CapabilitySet::from_capabilities([Capability::GetOpaque]),
        );
        assert_eq!(device.execute_inner(admin, &put).data, 42_u16.to_be_bytes());
        let set_audit = Frame::new(
            CommandCode::SetOption as u8,
            vec![
                OPTION_COMMAND_AUDIT,
                0,
                2,
                CommandCode::GetPseudoRandom as u8,
                OPTION_ON,
            ],
        )
        .unwrap();
        assert!(device.execute_inner(admin, &set_audit).data.is_empty());
        let random = Frame::new(CommandCode::GetPseudoRandom as u8, 4_u16.to_be_bytes()).unwrap();
        assert_eq!(device.execute_inner(admin, &random).data.len(), 4);
        assert_eq!(device.state_epoch(), 0);
        assert!(device.take_persistent_change().unwrap());
        assert_eq!(device.state_epoch(), 1);
        assert!(!device.take_persistent_change().unwrap());

        let encoded = device.persistent_state().unwrap();
        let mut restored = Device::from_persistent_state(config.clone(), &encoded).unwrap();
        assert_eq!(restored.state_epoch(), 1);
        assert_eq!(restored.active_session_count(), 0);
        assert!(
            restored
                .object(ObjectKey {
                    object_type: ObjectType::Opaque,
                    id: 42,
                })
                .is_some()
        );
        assert_eq!(restored.audit.entries.len(), 1);
        assert_eq!(
            restored.options.command_audit[&(CommandCode::GetPseudoRandom as u8)],
            OPTION_ON
        );
        assert_eq!(
            restored
                .device_static_private
                .serialized()
                .unwrap()
                .as_slice(),
            &[7; 32]
        );

        let reset = Frame::new(CommandCode::ResetDevice as u8, Vec::new()).unwrap();
        assert!(restored.execute_inner(admin, &reset).data.is_empty());
        assert_ne!(
            restored
                .device_static_private
                .serialized()
                .unwrap()
                .as_slice(),
            &[7; 32]
        );
        assert!(restored.take_persistent_change().unwrap());
        assert_eq!(restored.state_epoch(), 2);

        let reset_with_payload = Frame::new(CommandCode::ResetDevice as u8, vec![0xde]).unwrap();
        assert_eq!(
            DeviceError::from_byte(restored.execute_inner(admin, &reset_with_payload).data[0])
                .unwrap(),
            DeviceError::WrongLength
        );

        let foreign = DeviceConfig {
            serial: 78,
            ..config
        };
        assert_eq!(
            Device::from_persistent_state(foreign, &encoded).unwrap_err(),
            DeviceError::InvalidData
        );
    }

    #[test]
    fn persistent_state_uses_the_running_firmware_configuration() {
        let current = DeviceConfig::default();
        let mut previous = current.clone();
        previous.version = [2, 4, 1];
        previous
            .algorithms
            .retain(|algorithm| *algorithm != Algorithm::AesKwp as u8);
        let encoded = Device::factory_default(previous)
            .persistent_state()
            .unwrap();

        let restored = Device::from_persistent_state(current.clone(), &encoded).unwrap();
        let response =
            restored.execute_plain(&Frame::new(CommandCode::GetDeviceInfo as u8, vec![]).unwrap());
        assert_eq!(&response.data[..3], &current.version);
        assert!(
            response.data[9..].contains(&(Algorithm::AesKwp as u8)),
            "restored device must advertise capabilities of the running firmware"
        );

        let persisted: PersistentState =
            ciborium::from_reader(restored.persistent_state().unwrap().as_slice()).unwrap();
        assert_eq!(persisted.config.version, current.version);
        assert_eq!(persisted.config.algorithms, current.algorithms);
    }

    #[test]
    fn version_one_state_migrates_legacy_asymmetric_object_lengths() {
        let config = DeviceConfig {
            serial: 78,
            ..DeviceConfig::default()
        };
        let mut device = Device::factory_default(config.clone());
        let admin = device.session_authorization(1).unwrap();
        let generate = generate_asymmetric_key_request(
            43,
            1,
            CapabilitySet::from_capabilities([Capability::DeriveEcdh]),
            Algorithm::EcP224 as u8,
        );
        assert_eq!(
            device.execute_inner(admin, &generate).data,
            43_u16.to_be_bytes()
        );

        let current = device.persistent_state().unwrap();
        let mut legacy: PersistentState = ciborium::from_reader(current.as_slice()).unwrap();
        legacy.version = 1;
        for object in &mut legacy.objects {
            object.info.length = object.material.len().try_into().unwrap();
        }
        let mut encoded_legacy = Vec::new();
        ciborium::into_writer(&legacy, &mut encoded_legacy).unwrap();

        let restored = Device::from_persistent_state(config, &encoded_legacy).unwrap();
        assert_eq!(
            restored
                .object(ObjectKey {
                    object_type: ObjectType::AsymmetricKey,
                    id: 43,
                })
                .unwrap()
                .info
                .length,
            84
        );
        let upgraded: PersistentState =
            ciborium::from_reader(restored.persistent_state().unwrap().as_slice()).unwrap();
        assert_eq!(upgraded.version, PERSISTENT_STATE_VERSION);
    }

    #[test]
    fn version_two_state_migrates_measured_object_lengths() {
        let config = DeviceConfig {
            serial: 79,
            ..DeviceConfig::default()
        };
        let mut device = Device::factory_default(config.clone());
        let admin = device.session_authorization(1).unwrap();
        let generate = generate_asymmetric_key_request(
            44,
            1,
            CapabilitySet::from_capabilities([Capability::SignEddsa]),
            Algorithm::Ed25519 as u8,
        );
        assert_eq!(
            device.execute_inner(admin, &generate).data,
            44_u16.to_be_bytes()
        );

        let current = device.persistent_state().unwrap();
        let mut version_two: PersistentState = ciborium::from_reader(current.as_slice()).unwrap();
        version_two.version = 2;
        for object in &mut version_two.objects {
            let runtime = ObjectRecord::from_stored(object.clone()).unwrap();
            object.info.length = version_two_object_length(&runtime)
                .unwrap()
                .try_into()
                .unwrap();
        }
        let mut encoded_version_two = Vec::new();
        ciborium::into_writer(&version_two, &mut encoded_version_two).unwrap();

        let restored = Device::from_persistent_state(config, &encoded_version_two).unwrap();
        assert_eq!(
            restored
                .object(ObjectKey {
                    object_type: ObjectType::AuthenticationKey,
                    id: 1,
                })
                .unwrap()
                .info
                .length,
            40
        );
        assert_eq!(
            restored
                .object(ObjectKey {
                    object_type: ObjectType::AsymmetricKey,
                    id: 44,
                })
                .unwrap()
                .info
                .length,
            128
        );
    }

    #[test]
    fn authentication_commands_can_be_audited_but_session_message_cannot() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let enable_authentication_audit = Frame::new(
            CommandCode::SetOption as u8,
            vec![
                OPTION_COMMAND_AUDIT,
                0,
                4,
                CommandCode::CreateSession as u8,
                OPTION_ON,
                CommandCode::AuthenticateSession as u8,
                OPTION_ON,
            ],
        )
        .unwrap();
        assert!(
            device
                .execute_inner(admin, &enable_authentication_audit)
                .data
                .is_empty()
        );

        let mut create_data = 1_u16.to_be_bytes().to_vec();
        create_data.extend_from_slice(&[0; CHALLENGE_LENGTH]);
        let create = Frame::new(CommandCode::CreateSession as u8, create_data).unwrap();
        let create_response = device.handle_frame(create);
        assert_eq!(
            create_response.command,
            CommandCode::CreateSession as u8 | 0x80
        );
        let sid = create_response.data[0];

        let malformed_authenticate =
            Frame::new(CommandCode::AuthenticateSession as u8, vec![sid]).unwrap();
        assert_eq!(
            device.handle_frame(malformed_authenticate),
            Frame::error(DeviceError::AuthenticationFailed)
        );

        assert_eq!(device.audit.entries.len(), 2);
        assert_eq!(
            (
                device.audit.entries[0].command,
                device.audit.entries[0].session_key,
                device.audit.entries[0].target_key,
                device.audit.entries[0].result,
            ),
            (CommandCode::CreateSession as u8, 1, 1, 0)
        );
        assert_eq!(
            (
                device.audit.entries[1].command,
                device.audit.entries[1].session_key,
                device.audit.entries[1].target_key,
                device.audit.entries[1].result,
            ),
            (
                CommandCode::AuthenticateSession as u8,
                1,
                1,
                DeviceError::AuthenticationFailed as u8,
            )
        );

        let enable_session_message_audit = Frame::new(
            CommandCode::SetOption as u8,
            vec![
                OPTION_COMMAND_AUDIT,
                0,
                2,
                CommandCode::SessionMessage as u8,
                OPTION_ON,
            ],
        )
        .unwrap();
        assert_eq!(
            device.execute_inner(admin, &enable_session_message_audit),
            Frame::error(DeviceError::InvalidData)
        );

        for command in [
            CommandCode::Echo,
            CommandCode::GetDeviceInfo,
            CommandCode::GetDevicePublicKey,
            CommandCode::CloseSession,
        ] {
            let enable_audit = Frame::new(
                CommandCode::SetOption as u8,
                vec![OPTION_COMMAND_AUDIT, 0, 2, command as u8, OPTION_ON],
            )
            .unwrap();
            assert!(device.execute_inner(admin, &enable_audit).data.is_empty());
            assert_eq!(
                device.options.command_audit.get(&(command as u8)),
                Some(&OPTION_ON)
            );
            assert!(!device.should_audit(command));
        }
    }

    #[test]
    fn authentication_commands_are_not_denied_when_force_audit_log_is_full() {
        let mut device = Device::factory_default(DeviceConfig {
            log_capacity: 1,
            ..DeviceConfig::default()
        });
        let admin = device.session_authorization(1).unwrap();
        let options = Frame::new(
            CommandCode::SetOption as u8,
            vec![
                OPTION_COMMAND_AUDIT,
                0,
                4,
                CommandCode::CreateSession as u8,
                OPTION_ON,
                CommandCode::AuthenticateSession as u8,
                OPTION_ON,
            ],
        )
        .unwrap();
        assert!(device.execute_inner(admin, &options).data.is_empty());
        let force = Frame::new(
            CommandCode::SetOption as u8,
            vec![OPTION_FORCE_AUDIT, 0, 1, OPTION_ON],
        )
        .unwrap();
        assert!(device.execute_inner(admin, &force).data.is_empty());

        let mut create_data = 1_u16.to_be_bytes().to_vec();
        create_data.extend_from_slice(&[0; CHALLENGE_LENGTH]);
        let create = Frame::new(CommandCode::CreateSession as u8, create_data).unwrap();
        let first = device.handle_frame(create.clone());
        assert_eq!(first.command, CommandCode::CreateSession as u8 | 0x80);
        assert_eq!(device.audit.entries.len(), 1);

        let second = device.handle_frame(create);
        assert_eq!(second.command, CommandCode::CreateSession as u8 | 0x80);
        let sid = second.data[0];
        let malformed_authenticate =
            Frame::new(CommandCode::AuthenticateSession as u8, vec![sid]).unwrap();
        assert_eq!(
            device.handle_frame(malformed_authenticate),
            Frame::error(DeviceError::AuthenticationFailed)
        );
        assert_eq!(device.audit.entries.len(), 1);
    }

    #[test]
    fn blink_device_uses_the_official_one_byte_duration() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let blink = Frame::new(CommandCode::BlinkDevice as u8, vec![10]).unwrap();
        assert!(device.execute_inner(admin, &blink).data.is_empty());

        let missing_duration = Frame::new(CommandCode::BlinkDevice as u8, Vec::new()).unwrap();
        assert_eq!(
            device.execute_inner(admin, &missing_duration),
            Frame::error(DeviceError::WrongLength)
        );
    }
}
