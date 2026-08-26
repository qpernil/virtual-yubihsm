use crate::{
    session::{
        random_secret_key, secure_response_data_fits, secure_response_fits, SecureSession,
        SessionEntry, AUTHENTICATION_ALGORITHM_AES128_YUBICO, AUTHENTICATION_ALGORITHM_EC_P256,
        CHALLENGE_LENGTH, P256_PUBLIC_KEY_LENGTH,
    },
    Algorithm, AuthenticationKeyMaterial, Capability, CapabilitySet, CommandCode, DeviceError,
    Frame, ObjectInfo, ObjectKey, ObjectMaterial, ObjectRecord, ObjectType, Result,
    SessionAuthorization,
};
use const_oid::ObjectIdentifier;
use der::{
    asn1::{Any, BitString, OctetString},
    Decode, Encode,
};
use rsa::{pkcs8::EncodePublicKey as EncodeRsaPublicKey, BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use signature::{Keypair, Signer};
use software_key_core::{
    digest::{x963_kdf, HashAlgorithm},
    rsa_signing::RsaHashAlgorithm,
    secure_channel::yubico_password_kdf,
    software_key_agreement::{derive_with_signing_key, SoftwareX25519Key},
    software_signing::{EcCurve, SoftwarePublicKey, SoftwareSigningAlgorithm, SoftwareSigningKey},
    software_symmetric::{
        decrypt_aes_cbc, decrypt_aes_ccm, decrypt_aes_ecb, decrypt_yubico_otp_aead,
        encrypt_aes_cbc, encrypt_aes_ccm, encrypt_aes_ecb, encrypt_yubico_otp_aead, unwrap_aes_kwp,
        wrap_aes_kwp, AES_BLOCK_SIZE, AES_CCM_NONCE_SIZE, AES_CCM_TAG_SIZE,
    },
};
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding,
    SubjectPublicKeyInfoOwned,
};
use std::{collections::BTreeMap, io::Cursor};
use std::{str::FromStr, time::Duration};
use subtle::ConstantTimeEq;
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    certificate::TbsCertificate,
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
        Extension, ToExtension,
    },
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};
use zeroize::Zeroizing;

const MAX_OBJECTS: usize = 256;
const MAX_SESSIONS: u8 = 16;
const DEFAULT_AUTHENTICATION_ALGORITHM: u8 = AUTHENTICATION_ALGORITHM_AES128_YUBICO;
const OPAQUE_DATA_ALGORITHM: u8 = 30;
const PERSISTENT_STATE_SCHEMA: &str = "virtual-yubihsm-state";
const PERSISTENT_STATE_VERSION: u16 = 1;
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
    objects: Vec<ObjectRecord>,
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

#[derive(Clone)]
struct P256CertificateVerifyingKey(Vec<u8>);

impl spki::EncodePublicKey for P256CertificateVerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::Document> {
        let encoded = ec_subject_public_key_info(EcCurve::P256, &self.0)
            .map_err(|_| spki::Error::KeyMalformed)?
            .to_der()?;
        spki::Document::try_from(encoded).map_err(Into::into)
    }
}

struct P256CertificateSigner {
    key: SoftwareSigningKey,
    verifying_key: P256CertificateVerifyingKey,
}

impl P256CertificateSigner {
    fn from_serialized(serialized: &[u8]) -> Result<Self> {
        let key = SoftwareSigningKey::from_serialized(
            SoftwareSigningAlgorithm::EcdsaP256Sha256,
            serialized,
        )
        .map_err(|_| DeviceError::InvalidData)?;
        let SoftwarePublicKey::Ec {
            curve: EcCurve::P256,
            uncompressed,
        } = key.public_key()
        else {
            return Err(DeviceError::InvalidData);
        };
        Ok(Self {
            key,
            verifying_key: P256CertificateVerifyingKey(uncompressed),
        })
    }
}

impl Keypair for P256CertificateSigner {
    type VerifyingKey = P256CertificateVerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.verifying_key.clone()
    }
}

impl DynSignatureAlgorithmIdentifier for P256CertificateSigner {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        })
    }
}

struct P256CertificateSignature(Vec<u8>);

impl SignatureBitStringEncoding for P256CertificateSignature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::from_bytes(&self.0)
    }
}

impl Signer<P256CertificateSignature> for P256CertificateSigner {
    fn try_sign(
        &self,
        message: &[u8],
    ) -> core::result::Result<P256CertificateSignature, signature::Error> {
        self.key
            .sign_message(SoftwareSigningAlgorithm::EcdsaP256Sha256, message)
            .and_then(|signature| signature.to_ecdsa_der(EcCurve::P256))
            .map(P256CertificateSignature)
            .map_err(|_| signature::Error::new())
    }
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
            version: [2, 4, 1],
            serial: 12_345_678,
            log_capacity: 62,
            algorithms: Algorithm::OFFICIAL
                .into_iter()
                .chain([Algorithm::X25519, Algorithm::EcdhKdf])
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
    device_static_private: Zeroizing<[u8; 32]>,
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
        SoftwareSigningKey::from_serialized(
            SoftwareSigningAlgorithm::EcdsaP256Sha256,
            &device_static_private,
        )
        .map_err(|_| DeviceError::InvalidData)?;
        let mut device = Self {
            config,
            objects: BTreeMap::new(),
            sessions: BTreeMap::new(),
            device_static_private: Zeroizing::new(device_static_private),
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
            Some(_) => Err(DeviceError::InvalidSession),
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
            .unwrap_or_else(|| {
                if CommandCode::from_byte(request.command).is_some() {
                    Err(DeviceError::InvalidSession)
                } else {
                    Err(DeviceError::InvalidCommand)
                }
            });
        match result {
            Ok(data) => Frame::response(request.command, data),
            Err(error) => Frame::error(error),
        }
    }

    /// Commands accepted both directly and inside an authenticated session.
    fn execute_plain_or_authenticated(&self, request: &Frame) -> Option<Result<Vec<u8>>> {
        Some(match CommandCode::from_byte(request.command)? {
            CommandCode::Echo => Ok(request.data.clone()),
            CommandCode::GetDeviceInfo => self.get_device_info(&request.data),
            CommandCode::GetDevicePublicKey => self.get_device_public_key(&request.data),
            _ => return None,
        })
    }

    fn create_session(&mut self, request: &Frame) -> Result<Frame> {
        let data = &request.data;
        if data.len() < 2 {
            return Err(DeviceError::WrongLength);
        }
        let authentication_key_id = u16::from_be_bytes(data[..2].try_into().unwrap());
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
                    if data.len() != 2 + CHALLENGE_LENGTH {
                        return Err(DeviceError::WrongLength);
                    }
                    let mut card_challenge = [0; CHALLENGE_LENGTH];
                    getrandom::fill(&mut card_challenge).map_err(|_| DeviceError::StorageFailed)?;
                    let (secure, card_cryptogram, expected_host_cryptogram) =
                        SecureSession::begin_symmetric(
                            sid,
                            static_keys,
                            &data[2..],
                            card_challenge,
                        )?;
                    self.sessions.insert(
                        sid,
                        SessionEntry {
                            authorization,
                            secure,
                            expected_host_cryptogram: Some(expected_host_cryptogram),
                            authenticated: false,
                        },
                    );
                    let mut response = Vec::with_capacity(1 + CHALLENGE_LENGTH + 8);
                    response.push(sid);
                    response.extend_from_slice(&card_challenge);
                    response.extend_from_slice(&card_cryptogram);
                    Ok(Frame::response(CommandCode::CreateSession as u8, response))
                }
                AuthenticationKeyMaterial::Asymmetric(host_static_public) => {
                    if data.len() != 2 + P256_PUBLIC_KEY_LENGTH {
                        return Err(DeviceError::WrongLength);
                    }
                    let (secure, device_ephemeral_public, receipt) =
                        SecureSession::begin_asymmetric(
                            sid,
                            &self.device_static_private,
                            host_static_public,
                            &data[2..],
                        )?;
                    self.sessions.insert(
                        sid,
                        SessionEntry {
                            authorization,
                            secure,
                            expected_host_cryptogram: None,
                            authenticated: true,
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
        let sid = request
            .data
            .first()
            .copied()
            .ok_or(DeviceError::WrongLength)?;
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
        let sid = request
            .data
            .first()
            .copied()
            .ok_or(DeviceError::WrongLength)?;
        let mut entry = self
            .sessions
            .remove(&sid)
            .ok_or(DeviceError::InvalidSession)?;
        if !entry.authenticated {
            return Err(DeviceError::InvalidSession);
        }
        let inner = entry.secure.decrypt_request(request)?;
        let authorization_error = CommandCode::from_byte(inner.command)
            .and_then(CommandCode::required_session_capability)
            .and_then(|required| entry.authorization.require_capability(required).err());
        let handled_response = match authorization_error {
            Some(error) => Some(Frame::error(error)),
            None => handler(entry.authorization, &inner),
        };
        let handled_externally = handled_response.is_some();
        let response =
            handled_response.unwrap_or_else(|| self.execute_inner(entry.authorization, &inner));
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
        require_empty(data)?;
        let private = SoftwareSigningKey::from_serialized(
            SoftwareSigningAlgorithm::EcdsaP256Sha256,
            self.device_static_private.as_ref(),
        )
        .map_err(|_| DeviceError::StorageFailed)?;
        let SoftwarePublicKey::Ec {
            uncompressed: mut public,
            ..
        } = private.public_key()
        else {
            return Err(DeviceError::StorageFailed);
        };
        public[0] = AUTHENTICATION_ALGORITHM_EC_P256;
        Ok(public)
    }

    /// Execute an already decrypted session command under a snapshotted
    /// Authentication Key authorization context.
    pub fn execute_inner(&mut self, authorization: SessionAuthorization, request: &Frame) -> Frame {
        let command = CommandCode::from_byte(request.command);
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
            .execute_inner_result(authorization, request)
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

    /// Invalidate every volatile secure session without changing objects.
    pub fn clear_sessions(&mut self) {
        self.sessions.clear();
    }

    /// Encode durable device state. Secure sessions and transport counters are
    /// intentionally excluded, just as they are on a physical power cycle.
    pub fn persistent_state(&self) -> Result<Vec<u8>> {
        let state = PersistentState {
            schema: PERSISTENT_STATE_SCHEMA.to_owned(),
            version: PERSISTENT_STATE_VERSION,
            config: self.config.clone(),
            objects: self.objects.values().cloned().collect(),
            device_static_private: *self.device_static_private,
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
            || state.version != PERSISTENT_STATE_VERSION
            || state.config.serial != config.serial
            || state.audit.entries.len() > usize::from(state.config.log_capacity)
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
        SoftwareSigningKey::from_serialized(
            SoftwareSigningAlgorithm::EcdsaP256Sha256,
            &state.device_static_private,
        )
        .map_err(|_| DeviceError::InvalidData)?;
        let sequence_history = state.sequence_history;
        if !sequence_history.validate() {
            return Err(DeviceError::InvalidData);
        }
        let mut objects = BTreeMap::new();
        for object in state.objects {
            object.validate()?;
            let key = object.info.key();
            if objects.insert(key, object).is_some() {
                return Err(DeviceError::InvalidData);
            }
        }
        Ok(Self {
            config: state.config,
            objects,
            sessions: BTreeMap::new(),
            device_static_private: Zeroizing::new(state.device_static_private),
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
    ) -> Result<Vec<u8>> {
        if let Some(result) = self.execute_plain_or_authenticated(request) {
            return result;
        }
        let command = CommandCode::from_byte(request.command).ok_or(DeviceError::InvalidCommand)?;
        self.authorize_command_request(authorization, command, &request.data)?;
        match command {
            CommandCode::CloseSession => require_empty(&request.data).map(|()| Vec::new()),
            CommandCode::GetStorageInfo => {
                require_empty(&request.data)?;
                let used = self.objects.len() as u16;
                let free = MAX_OBJECTS.saturating_sub(self.objects.len()) as u16;
                Ok([MAX_OBJECTS as u16, free, 1024, 1024 - used, 126]
                    .into_iter()
                    .flat_map(u16::to_be_bytes)
                    .collect())
            }
            CommandCode::GetPseudoRandom => {
                let length = parse_u16(&request.data)? as usize;
                let mut output = vec![0; length];
                getrandom::fill(&mut output).map_err(|_| DeviceError::StorageFailed)?;
                Ok(output)
            }
            CommandCode::ListObjects => self.list_objects(authorization, &request.data),
            CommandCode::GetObjectInfo => {
                let key = parse_object_key(&request.data)?;
                let object = self.objects.get(&key).ok_or(DeviceError::ObjectNotFound)?;
                authorization.require_visible(&object.info)?;
                Ok(object.info.encode().to_vec())
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
            CommandCode::DeriveEcdh => self.derive_ecdh(authorization, &request.data),
            CommandCode::DeriveEcdhKdf => self.derive_ecdh_kdf(authorization, &request.data),
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
                let id = parse_u16(&request.data)?;
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
                let key = parse_object_key(&request.data)?;
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
                if request.data != [0xde] {
                    return Err(DeviceError::InvalidData);
                }
                let renewed_device_static_private = random_device_static_private()?;
                self.objects.clear();
                self.sequence_history.clear();
                self.sessions.clear();
                *self.device_static_private = renewed_device_static_private;
                self.options = DeviceOptions::default();
                self.audit = AuditState {
                    next_number: 1,
                    ..AuditState::default()
                };
                self.install_factory_authentication_key();
                Ok(Vec::new())
            }
            CommandCode::BlinkDevice => {
                if request.data.len() != 1 {
                    return Err(DeviceError::WrongLength);
                }
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

        let first = |object_type, capability| {
            self.authorize_object_at(authorization, data, 0, object_type, capability)
        };
        match command {
            CommandCode::PutOpaque => {
                if data.len() < 2 {
                    return Err(DeviceError::WrongLength);
                }
                let id = parse_u16_at(data, 0)?;
                if id != 0
                    && self.objects.contains_key(&ObjectKey {
                        object_type: ObjectType::Opaque,
                        id,
                    })
                {
                    first(ObjectType::Opaque, Capability::PutOpaque)
                } else {
                    Ok(())
                }
            }
            CommandCode::GetOpaque => first(ObjectType::Opaque, Capability::GetOpaque),
            CommandCode::GetTemplate => first(ObjectType::Template, Capability::GetTemplate),
            CommandCode::ChangeAuthenticationKey => {
                if parse_u16_at(data, 0)? != authorization.authentication_key_id {
                    return Err(DeviceError::InvalidId);
                }
                first(
                    ObjectType::AuthenticationKey,
                    Capability::ChangeAuthenticationKey,
                )
            }
            CommandCode::SignPkcs1 => first(ObjectType::AsymmetricKey, Capability::SignPkcs),
            CommandCode::SignPss => first(ObjectType::AsymmetricKey, Capability::SignPss),
            CommandCode::SignEcdsa => first(ObjectType::AsymmetricKey, Capability::SignEcdsa),
            CommandCode::SignEddsa => first(ObjectType::AsymmetricKey, Capability::SignEddsa),
            CommandCode::DeriveEcdh => first(ObjectType::AsymmetricKey, Capability::DeriveEcdh),
            CommandCode::DeriveEcdhKdf => {
                first(ObjectType::AsymmetricKey, Capability::DeriveEcdhKdf)
            }
            CommandCode::DecryptPkcs1 => first(ObjectType::AsymmetricKey, Capability::DecryptPkcs),
            CommandCode::DecryptOaep => first(ObjectType::AsymmetricKey, Capability::DecryptOaep),
            CommandCode::SignHmac => first(ObjectType::HmacKey, Capability::SignHmac),
            CommandCode::VerifyHmac => first(ObjectType::HmacKey, Capability::VerifyHmac),
            CommandCode::WrapData => first(ObjectType::WrapKey, Capability::WrapData),
            CommandCode::UnwrapData => first(ObjectType::WrapKey, Capability::UnwrapData),
            CommandCode::EncryptEcb => first(ObjectType::SymmetricKey, Capability::EncryptEcb),
            CommandCode::DecryptEcb => first(ObjectType::SymmetricKey, Capability::DecryptEcb),
            CommandCode::EncryptCbc => first(ObjectType::SymmetricKey, Capability::EncryptCbc),
            CommandCode::DecryptCbc => first(ObjectType::SymmetricKey, Capability::DecryptCbc),
            CommandCode::CreateOtpAead => first(ObjectType::OtpAeadKey, Capability::CreateOtpAead),
            CommandCode::RandomizeOtpAead => {
                first(ObjectType::OtpAeadKey, Capability::RandomizeOtpAead)
            }
            CommandCode::DecryptOtp => first(ObjectType::OtpAeadKey, Capability::DecryptOtp),
            CommandCode::RewrapOtpAead => {
                self.authorize_object_at(
                    authorization,
                    data,
                    0,
                    ObjectType::OtpAeadKey,
                    Capability::RewrapFromOtpAeadKey,
                )?;
                self.authorize_object_at(
                    authorization,
                    data,
                    2,
                    ObjectType::OtpAeadKey,
                    Capability::RewrapToOtpAeadKey,
                )
            }
            CommandCode::ExportWrapped => {
                self.authorize_wrapped_export_request(authorization, data, ObjectType::WrapKey)
            }
            CommandCode::GetRsaWrappedKey | CommandCode::ExportRsaWrapped => self
                .authorize_wrapped_export_request(authorization, data, ObjectType::PublicWrapKey),
            CommandCode::ImportWrapped
            | CommandCode::ImportRsaWrapped
            | CommandCode::PutRsaWrappedKey => {
                first(ObjectType::WrapKey, Capability::ImportWrapped)
            }
            CommandCode::SignAttestationCertificate => {
                if data.len() != 4 {
                    return Err(DeviceError::WrongLength);
                }
                let target_id = parse_u16_at(data, 0)?;
                if target_id != 0 {
                    self.require_object_visible(
                        authorization,
                        ObjectKey {
                            object_type: ObjectType::AsymmetricKey,
                            id: target_id,
                        },
                    )?;
                }
                let attesting_id = parse_u16_at(data, 2)?;
                if attesting_id != 0 {
                    self.authorize_object(
                        authorization,
                        ObjectKey {
                            object_type: ObjectType::AsymmetricKey,
                            id: attesting_id,
                        },
                        Capability::SignAttestationCertificate,
                    )?;
                    if self.objects.contains_key(&ObjectKey {
                        object_type: ObjectType::Opaque,
                        id: attesting_id,
                    }) {
                        self.require_object_visible(
                            authorization,
                            ObjectKey {
                                object_type: ObjectType::Opaque,
                                id: attesting_id,
                            },
                        )?;
                    }
                }
                Ok(())
            }
            CommandCode::GetObjectInfo => {
                self.require_object_visible(authorization, parse_object_key(data)?)
            }
            CommandCode::GetPublicKey => {
                if !matches!(data.len(), 2 | 3) {
                    return Err(DeviceError::WrongLength);
                }
                let object_type = match data.get(2) {
                    Some(value) => ObjectType::from_byte(*value).ok_or(DeviceError::InvalidData)?,
                    None => ObjectType::AsymmetricKey,
                };
                self.require_object_visible(
                    authorization,
                    ObjectKey {
                        object_type,
                        id: parse_u16_at(data, 0)?,
                    },
                )
            }
            CommandCode::DeleteObject => {
                let key = parse_object_key(data)?;
                let object = self.objects.get(&key).ok_or(DeviceError::ObjectNotFound)?;
                authorization.authorize_delete(&object.info)
            }
            _ => Ok(()),
        }
    }

    fn authorize_object_at(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
        offset: usize,
        object_type: ObjectType,
        capability: Capability,
    ) -> Result<()> {
        self.authorize_object(
            authorization,
            ObjectKey {
                object_type,
                id: parse_u16_at(data, offset)?,
            },
            capability,
        )
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

    fn authorize_wrapped_export_request(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
        wrap_key_type: ObjectType,
    ) -> Result<()> {
        if data.len() < 5 {
            return Err(DeviceError::WrongLength);
        }
        let wrap_key = self
            .objects
            .get(&ObjectKey {
                object_type: wrap_key_type,
                id: parse_u16_at(data, 0)?,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        let target = self
            .objects
            .get(&ObjectKey {
                object_type: ObjectType::from_byte(data[2]).ok_or(DeviceError::InvalidData)?,
                id: parse_u16_at(data, 3)?,
            })
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.authorize_wrapped_export(target, wrap_key)
    }

    fn get_device_info(&self, data: &[u8]) -> Result<Vec<u8>> {
        match data {
            [] => {
                let algorithms = self.enabled_algorithms();
                let mut output = Vec::with_capacity(9 + algorithms.len());
                output.extend_from_slice(&self.config.version);
                output.extend_from_slice(&self.config.serial.to_be_bytes());
                output.push(self.config.log_capacity);
                output.push(self.audit.entries.len().try_into().unwrap_or(u8::MAX));
                output.extend_from_slice(&algorithms);
                Ok(output)
            }
            [1] => Ok(self.config.part_number.to_vec()),
            _ => Err(DeviceError::InvalidData),
        }
    }

    fn get_log_entries(&self, data: &[u8]) -> Result<Vec<u8>> {
        require_empty(data)?;
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
        let index = parse_u16(data)?;
        self.audit.entries.retain(|entry| entry.number > index);
        Ok(Vec::new())
    }

    fn get_option(&self, data: &[u8]) -> Result<Vec<u8>> {
        let &[option] = data else {
            return Err(DeviceError::WrongLength);
        };
        match option {
            OPTION_FORCE_AUDIT => Ok(vec![self.options.force_audit]),
            OPTION_COMMAND_AUDIT => {
                let mut output = Vec::new();
                for command in 0..=u8::MAX {
                    if CommandCode::from_byte(command).is_some() {
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
                for algorithm in &self.config.algorithms {
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
        if data.len() < 3 {
            return Err(DeviceError::WrongLength);
        }
        let option = data[0];
        let value_length = u16::from_be_bytes(data[1..3].try_into().unwrap()) as usize;
        if data.len() != 3 + value_length {
            return Err(DeviceError::WrongLength);
        }
        let values = &data[3..];
        match option {
            OPTION_FORCE_AUDIT => {
                let &[value] = values else {
                    return Err(DeviceError::WrongLength);
                };
                set_option_value(&mut self.options.force_audit, value)?;
            }
            OPTION_COMMAND_AUDIT => {
                if values.is_empty() || values.len() % 2 != 0 {
                    return Err(DeviceError::WrongLength);
                }
                let mut updated = self.options.command_audit.clone();
                for pair in values.chunks_exact(2) {
                    let Some(command) = CommandCode::from_byte(pair[0]) else {
                        return Err(DeviceError::InvalidData);
                    };
                    if !valid_option_value(pair[1]) {
                        return Err(DeviceError::InvalidData);
                    }
                    if !command_can_be_audited(command) && pair[1] != OPTION_OFF {
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
                if values.is_empty() || values.len() % 2 != 0 {
                    return Err(DeviceError::WrongLength);
                }
                let mut updated = self.options.algorithm_toggle.clone();
                for pair in values.chunks_exact(2) {
                    if !self.config.algorithms.contains(&pair[0]) || !valid_option_value(pair[1]) {
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
        self.options
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

    fn list_objects(&self, authorization: SessionAuthorization, filters: &[u8]) -> Result<Vec<u8>> {
        let filters = ObjectFilters::parse(filters)?;
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
        if data.len() < 53 {
            return Err(DeviceError::WrongLength);
        }
        self.require_algorithm_enabled(data[52])?;
        let requested_id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let capabilities = CapabilitySet::from_bytes(data[44..52].try_into().unwrap());
        let domains = u16::from_be_bytes(data[42..44].try_into().unwrap());
        let algorithm = data[52];
        let label = trim_label(&data[2..42]);
        let material = data[53..].to_vec();
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
        const HEADER_LENGTH: usize = 61;
        if data.len() < HEADER_LENGTH {
            return Err(DeviceError::WrongLength);
        }
        let algorithm = data[52];
        self.require_algorithm_enabled(algorithm)?;
        let key_length = authentication_key_length(algorithm)?;
        if data.len() != HEADER_LENGTH + key_length {
            return Err(DeviceError::WrongLength);
        }
        let id = self.resolve_id(
            ObjectType::AuthenticationKey,
            u16::from_be_bytes(data[..2].try_into().unwrap()),
        )?;
        let info = ObjectInfo {
            capabilities: CapabilitySet::from_bytes(data[44..52].try_into().unwrap()),
            id,
            length: key_length as u16,
            domains: u16::from_be_bytes(data[42..44].try_into().unwrap()),
            object_type: ObjectType::AuthenticationKey,
            algorithm,
            sequence: 0,
            origin: 2,
            label: trim_label(&data[2..42]),
            delegated_capabilities: CapabilitySet::from_bytes(data[53..61].try_into().unwrap()),
        };
        authorization.authorize_create(&info, Capability::PutAuthenticationKey)?;
        let material = parse_authentication_key_material(algorithm, &data[HEADER_LENGTH..])?;
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
        const HEADER_LENGTH: usize = 53;
        if data.len() < HEADER_LENGTH || (generate && data.len() != HEADER_LENGTH) {
            return Err(DeviceError::WrongLength);
        }
        let algorithm = Algorithm::from_byte(data[52]).ok_or(DeviceError::InvalidData)?;
        self.require_algorithm_enabled(algorithm as u8)?;
        let expected_length = algorithm
            .asymmetric_key_length()
            .ok_or(DeviceError::InvalidData)?;
        let supplied = &data[HEADER_LENGTH..];
        let secret = asymmetric_key_material(algorithm, generate, supplied)?;
        if secret.len() != expected_length {
            return Err(DeviceError::InvalidData);
        }
        let id = self.resolve_id(
            ObjectType::AsymmetricKey,
            u16::from_be_bytes(data[..2].try_into().unwrap()),
        )?;
        let capability = if generate {
            Capability::GenerateAsymmetricKey
        } else {
            Capability::PutAsymmetricKey
        };
        let info = ObjectInfo {
            capabilities: CapabilitySet::from_bytes(data[44..52].try_into().unwrap()),
            id,
            length: expected_length as u16,
            domains: u16::from_be_bytes(data[42..44].try_into().unwrap()),
            object_type: ObjectType::AsymmetricKey,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: if generate { 1 } else { 2 },
            label: trim_label(&data[2..42]),
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

    fn get_public_key(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if !matches!(data.len(), 2 | 3) {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object_type = match data.get(2) {
            Some(value) => ObjectType::from_byte(*value).ok_or(DeviceError::InvalidData)?,
            None => ObjectType::AsymmetricKey,
        };
        if !matches!(
            object_type,
            ObjectType::AsymmetricKey | ObjectType::WrapKey | ObjectType::PublicWrapKey
        ) {
            return Err(DeviceError::InvalidData);
        }
        let object = self
            .objects
            .get(&ObjectKey { object_type, id })
            .ok_or(DeviceError::ObjectNotFound)?;
        authorization.require_visible(&object.info)?;
        let mut output = vec![object.info.algorithm];
        if object.info.object_type == ObjectType::PublicWrapKey {
            match &object.material {
                ObjectMaterial::Public(public) => output.extend_from_slice(public),
                _ => return Err(DeviceError::InvalidData),
            }
        } else if object.info.algorithm == Algorithm::X25519 as u8 {
            output.extend_from_slice(&x25519_key(object)?.public_key());
        } else {
            match signing_key(object)?.public_key() {
                SoftwarePublicKey::Ec { uncompressed, .. } => {
                    output.extend_from_slice(&uncompressed[1..]);
                }
                SoftwarePublicKey::Ed25519(public) => output.extend_from_slice(&public),
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
        if data.len() != 4 {
            return Err(DeviceError::WrongLength);
        }
        let target_id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let attesting_id = u16::from_be_bytes(data[2..].try_into().unwrap());
        let (target_spki, target_info) = if target_id == 0 {
            let private = SoftwareSigningKey::from_serialized(
                SoftwareSigningAlgorithm::EcdsaP256Sha256,
                self.device_static_private.as_ref(),
            )
            .map_err(|_| DeviceError::StorageFailed)?;
            let SoftwarePublicKey::Ec {
                uncompressed: public,
                ..
            } = private.public_key()
            else {
                return Err(DeviceError::StorageFailed);
            };
            (
                ec_subject_public_key_info(EcCurve::P256, &public)?,
                ObjectInfo {
                    capabilities: CapabilitySet::NONE,
                    id: 0,
                    length: 32,
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
                *self.device_static_private,
                format!("CN=Virtual YubiHSM {} Attestation", self.config.serial),
            )
        } else {
            let attesting = self.asymmetric_object(authorization, attesting_id)?;
            if attesting.info.algorithm != Algorithm::EcP256 as u8 {
                return Err(DeviceError::InvalidData);
            }
            let secret: [u8; 32] = object_secret(attesting)?
                .try_into()
                .map_err(|_| DeviceError::InvalidData)?;
            (
                secret,
                format!("CN=Virtual YubiHSM Attestation Key {attesting_id}"),
            )
        };
        let signer = P256CertificateSigner::from_serialized(&attesting_private)?;
        let mut subject = Name::from_str(&format!("CN=Virtual YubiHSM Key {target_id}"))
            .map_err(|_| DeviceError::InvalidData)?;
        let mut issuer = Name::from_str(&issuer).map_err(|_| DeviceError::InvalidData)?;
        let mut validity = Validity::from_now(Duration::from_secs(10 * 365 * 86_400))
            .map_err(|_| DeviceError::StorageFailed)?;
        let mut template_extensions = Vec::new();
        if attesting_id != 0 {
            if let Some(template) = self.objects.get(&ObjectKey {
                object_type: ObjectType::Opaque,
                id: attesting_id,
            }) {
                authorization.require_visible(&template.info)?;
                if template.info.algorithm != Algorithm::OpaqueX509Certificate as u8 {
                    return Err(DeviceError::InvalidData);
                }
                let ObjectMaterial::Opaque(encoded) = &template.material else {
                    return Err(DeviceError::InvalidData);
                };
                let certificate = x509_cert::Certificate::from_der(encoded)
                    .map_err(|_| DeviceError::InvalidData)?;
                let tbs = certificate.tbs_certificate();
                subject = tbs.subject().clone();
                issuer = tbs.issuer().clone();
                validity = *tbs.validity();
                template_extensions = tbs.extensions().cloned().unwrap_or_default();
            }
        }
        let algorithm =
            Algorithm::from_byte(target_info.algorithm).ok_or(DeviceError::InvalidData)?;
        let profile = AttestationProfile {
            subject,
            issuer,
            key_agreement: matches!(algorithm, Algorithm::Ecdh | Algorithm::X25519)
                || algorithm.is_weierstrass_key(),
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
            .build::<_, P256CertificateSignature>(&signer)
            .map_err(|_| DeviceError::StorageFailed)?;
        certificate.to_der().map_err(|_| DeviceError::StorageFailed)
    }

    fn sign_pkcs1(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 3 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.asymmetric_object(authorization, id)?;
        let key = rsa_key(object)?;
        let payload = &data[2..];
        let signature = match rsa_hash_from_digest_length(payload.len()) {
            Some(hash) => key.sign_rsa_pkcs1v15_digest(hash, payload),
            None => key.sign_rsa_pkcs1v15_payload(payload),
        };
        signature
            .map(|signature| signature.into_bytes())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn sign_pss(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 6 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.asymmetric_object(authorization, id)?;
        let mgf_hash = rsa_mgf_hash(data[2])?;
        let salt_length = u16::from_be_bytes(data[3..5].try_into().unwrap()) as usize;
        let digest = &data[5..];
        let hash = rsa_hash_from_digest_length(digest.len()).ok_or(DeviceError::WrongLength)?;
        rsa_key(object)?
            .sign_rsa_pss_digest(hash, mgf_hash, salt_length, digest)
            .map(|signature| signature.into_bytes())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn sign_ecdsa(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 3 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.asymmetric_object(authorization, id)?;
        let (algorithm, _) = asymmetric_key_algorithm(object.info.algorithm)?;
        if matches!(algorithm, SoftwareSigningAlgorithm::Ed25519) {
            return Err(DeviceError::InvalidData);
        }
        signing_key(object)?
            .sign_prehash(algorithm, &data[2..])
            .map(|signature| signature.into_bytes())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn sign_eddsa(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 2 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.asymmetric_object(authorization, id)?;
        if object.info.algorithm != 46 {
            return Err(DeviceError::InvalidData);
        }
        signing_key(object)?
            .sign_message(SoftwareSigningAlgorithm::Ed25519, &data[2..])
            .map(|signature| signature.into_bytes())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn derive_ecdh(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 3 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.asymmetric_object(authorization, id)?;
        raw_ecdh_secret(object, &data[2..]).map(|secret| secret.to_vec())
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
        const HEADER_LENGTH: usize = 11;
        if data.len() < HEADER_LENGTH {
            return Err(DeviceError::WrongLength);
        }
        let id = parse_u16_at(data, 0)?;
        let hash = ecdh_kdf_hash(data[2])?;
        let output_length = usize::from(parse_u16_at(data, 3)?);
        if output_length == 0 || !secure_response_data_fits(output_length) {
            return Err(DeviceError::WrongLength);
        }
        let lengths = [
            usize::from(parse_u16_at(data, 5)?),
            usize::from(parse_u16_at(data, 7)?),
            usize::from(parse_u16_at(data, 9)?),
        ];
        let payload_length = lengths
            .into_iter()
            .try_fold(0_usize, usize::checked_add)
            .ok_or(DeviceError::WrongLength)?;
        if data.len() != HEADER_LENGTH.saturating_add(payload_length) {
            return Err(DeviceError::WrongLength);
        }
        let mut offset = HEADER_LENGTH;
        let mut take = |length: usize| {
            let value = &data[offset..offset + length];
            offset += length;
            value
        };
        let peer_public = take(lengths[0]);
        let prefix = take(lengths[1]);
        let shared_info = take(lengths[2]);

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

    fn decrypt_pkcs1(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 3 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.asymmetric_object(authorization, id)?;
        rsa_key(object)?
            .decrypt_rsa_pkcs1v15(&data[2..])
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| DeviceError::InvalidData)
    }

    fn decrypt_oaep(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 3 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.asymmetric_object(authorization, id)?;
        let modulus_length = object.info.length as usize;
        let digest_length = data
            .len()
            .checked_sub(3 + modulus_length)
            .ok_or(DeviceError::WrongLength)?;
        if !matches!(digest_length, 20 | 32 | 48 | 64) {
            return Err(DeviceError::WrongLength);
        }
        let mgf_hash = rsa_mgf_hash(data[2])?;
        let ciphertext_end = 3 + modulus_length;
        rsa_key(object)?
            .decrypt_rsa_oaep_digest(&data[3..ciphertext_end], &data[ciphertext_end..], mgf_hash)
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
        const HEADER_LENGTH: usize = 53;
        if data.len() < HEADER_LENGTH || (generate && data.len() != HEADER_LENGTH) {
            return Err(DeviceError::WrongLength);
        }
        let algorithm = data[52];
        self.require_algorithm_enabled(algorithm)?;
        let generated_length = hmac_length(algorithm)?;
        let secret = if generate {
            let mut value = vec![0; generated_length];
            getrandom::fill(&mut value).map_err(|_| DeviceError::StorageFailed)?;
            value
        } else {
            let value = data[HEADER_LENGTH..].to_vec();
            if value.is_empty() || value.len() > 128 {
                return Err(DeviceError::WrongLength);
            }
            value
        };
        let id = self.resolve_id(
            ObjectType::HmacKey,
            u16::from_be_bytes(data[..2].try_into().unwrap()),
        )?;
        let capability = if generate {
            Capability::GenerateHmacKey
        } else {
            Capability::PutMacKey
        };
        let info = ObjectInfo {
            capabilities: CapabilitySet::from_bytes(data[44..52].try_into().unwrap()),
            id,
            length: secret.len() as u16,
            domains: u16::from_be_bytes(data[42..44].try_into().unwrap()),
            object_type: ObjectType::HmacKey,
            algorithm,
            sequence: 0,
            origin: if generate { 1 } else { 2 },
            label: trim_label(&data[2..42]),
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
        const HEADER_LENGTH: usize = 53;
        if data.len() < HEADER_LENGTH || (generate && data.len() != HEADER_LENGTH) {
            return Err(DeviceError::WrongLength);
        }
        let algorithm = Algorithm::from_byte(data[52]).ok_or(DeviceError::InvalidData)?;
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
            if data.len() != HEADER_LENGTH + key_length {
                return Err(DeviceError::WrongLength);
            }
            data[HEADER_LENGTH..].to_vec()
        };
        let id = self.resolve_id(
            ObjectType::SymmetricKey,
            u16::from_be_bytes(data[..2].try_into().unwrap()),
        )?;
        let capability = if generate {
            Capability::GenerateSymmetricKey
        } else {
            Capability::PutSymmetricKey
        };
        let info = ObjectInfo {
            capabilities: CapabilitySet::from_bytes(data[44..52].try_into().unwrap()),
            id,
            length: key_length as u16,
            domains: u16::from_be_bytes(data[42..44].try_into().unwrap()),
            object_type: ObjectType::SymmetricKey,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: if generate { 1 } else { 2 },
            label: trim_label(&data[2..42]),
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
        const HEADER_LENGTH: usize = 61;
        if data.len() < HEADER_LENGTH || (generate && data.len() != HEADER_LENGTH) {
            return Err(DeviceError::WrongLength);
        }
        let algorithm = Algorithm::from_byte(data[52]).ok_or(DeviceError::InvalidData)?;
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
        let secret = if algorithm.is_rsa_key() {
            asymmetric_key_material(algorithm, generate, &data[HEADER_LENGTH..])?
        } else if generate {
            let mut secret = vec![0; key_length];
            getrandom::fill(&mut secret).map_err(|_| DeviceError::StorageFailed)?;
            secret
        } else {
            if data.len() != HEADER_LENGTH + key_length {
                return Err(DeviceError::WrongLength);
            }
            data[HEADER_LENGTH..].to_vec()
        };
        let id = self.resolve_id(
            ObjectType::WrapKey,
            u16::from_be_bytes(data[..2].try_into().unwrap()),
        )?;
        let capability = if generate {
            Capability::GenerateWrapKey
        } else {
            Capability::PutWrapKey
        };
        let info = ObjectInfo {
            capabilities: CapabilitySet::from_bytes(data[44..52].try_into().unwrap()),
            id,
            length: key_length as u16,
            domains: u16::from_be_bytes(data[42..44].try_into().unwrap()),
            object_type: ObjectType::WrapKey,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: if generate { 1 } else { 2 },
            label: trim_label(&data[2..42]),
            delegated_capabilities: CapabilitySet::from_bytes(data[53..61].try_into().unwrap()),
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

    fn put_public_wrap_key(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        const HEADER_LENGTH: usize = 61;
        if data.len() < HEADER_LENGTH {
            return Err(DeviceError::WrongLength);
        }
        let algorithm = Algorithm::from_byte(data[52]).ok_or(DeviceError::InvalidData)?;
        self.require_algorithm_enabled(algorithm as u8)?;
        if !algorithm.is_rsa_key() {
            return Err(DeviceError::InvalidData);
        }
        let key_length = algorithm.asymmetric_key_length().unwrap();
        if data.len() != HEADER_LENGTH + key_length {
            return Err(DeviceError::WrongLength);
        }
        let id = self.resolve_id(
            ObjectType::PublicWrapKey,
            u16::from_be_bytes(data[..2].try_into().unwrap()),
        )?;
        let info = ObjectInfo {
            capabilities: CapabilitySet::from_bytes(data[44..52].try_into().unwrap()),
            id,
            length: key_length as u16,
            domains: u16::from_be_bytes(data[42..44].try_into().unwrap()),
            object_type: ObjectType::PublicWrapKey,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: 2,
            label: trim_label(&data[2..42]),
            delegated_capabilities: CapabilitySet::from_bytes(data[53..61].try_into().unwrap()),
        };
        authorization.authorize_create(&info, Capability::PutPublicWrapKey)?;
        let record = ObjectRecord {
            info,
            material: ObjectMaterial::Public(data[HEADER_LENGTH..].to_vec()),
        };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn wrap_data(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 2 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.ccm_wrap_key(authorization, id)?;
        let mut nonce = [0; AES_CCM_NONCE_SIZE];
        getrandom::fill(&mut nonce).map_err(|_| DeviceError::StorageFailed)?;
        let encrypted = encrypt_aes_ccm(object_secret(object)?, &nonce, &data[2..])
            .map_err(|_| DeviceError::InvalidData)?;
        let mut output = Vec::with_capacity(1 + AES_CCM_NONCE_SIZE + encrypted.len());
        output.push(1);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&encrypted);
        Ok(output)
    }

    fn unwrap_data(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        const OVERHEAD: usize = 1 + AES_CCM_NONCE_SIZE + AES_CCM_TAG_SIZE;
        if data.len() < 2 + OVERHEAD || data[2] != 1 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.ccm_wrap_key(authorization, id)?;
        decrypt_aes_ccm(
            object_secret(object)?,
            &data[3..3 + AES_CCM_NONCE_SIZE],
            &data[3 + AES_CCM_NONCE_SIZE..],
        )
        .map_err(|_| DeviceError::InvalidData)
    }

    fn export_wrapped(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if !matches!(data.len(), 5 | 6) || data.get(5).is_some_and(|format| *format > 1) {
            return Err(DeviceError::WrongLength);
        }
        let wrap_id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let target_key = ObjectKey {
            object_type: ObjectType::from_byte(data[2]).ok_or(DeviceError::InvalidData)?,
            id: u16::from_be_bytes(data[3..5].try_into().unwrap()),
        };
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
        const MINIMUM_LENGTH: usize = 2 + 1 + AES_CCM_NONCE_SIZE + AES_CCM_TAG_SIZE;
        if data.len() < MINIMUM_LENGTH || data[2] != 1 {
            return Err(DeviceError::WrongLength);
        }
        let wrap_id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let mut record = {
            let wrap_key = self.ccm_wrap_key(authorization, wrap_id)?;
            let plaintext = decrypt_aes_ccm(
                object_secret(wrap_key)?,
                &data[3..3 + AES_CCM_NONCE_SIZE],
                &data[3 + AES_CCM_NONCE_SIZE..],
            )
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
        if data.len() < 8 {
            return Err(DeviceError::WrongLength);
        }
        let label_length = rsa_oaep_hash(data[6])?.output_length();
        if data.len() != 8 + label_length {
            return Err(DeviceError::WrongLength);
        }
        let wrap_id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let target_key = ObjectKey {
            object_type: ObjectType::from_byte(data[2]).ok_or(DeviceError::InvalidData)?,
            id: u16::from_be_bytes(data[3..5].try_into().unwrap()),
        };
        if key_material_only
            && !matches!(
                target_key.object_type,
                ObjectType::AsymmetricKey | ObjectType::SymmetricKey
            )
        {
            return Err(DeviceError::InvalidData);
        }
        let aes_length = rsa_wrap_aes_length(data[5])?;
        let mgf_hash = rsa_mgf_hash(data[7])?;
        let wrap_key = self.rsa_public_wrap_key(authorization, wrap_id)?;
        let target = self
            .objects
            .get(&target_key)
            .ok_or(DeviceError::ObjectNotFound)?;
        let plaintext = if key_material_only {
            match target_key.object_type {
                ObjectType::AsymmetricKey => signing_key(target)?
                    .to_pkcs8_der()
                    .map_err(|_| DeviceError::InvalidData)?
                    .to_vec(),
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
        rsa_aes_wrap(&public, aes_length, &plaintext, &data[8..], mgf_hash)
    }

    fn import_rsa_wrapped(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if data.len() < 4 {
            return Err(DeviceError::WrongLength);
        }
        let label_length = rsa_oaep_hash(data[2])?.output_length();
        let wrap_id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let mgf_hash = rsa_mgf_hash(data[3])?;
        let mut record = {
            let wrap_key = self.rsa_private_wrap_key(authorization, wrap_id)?;
            let modulus_length = wrap_key.info.length as usize;
            if data.len() < 4 + modulus_length + 16 + label_length {
                return Err(DeviceError::WrongLength);
            }
            let wrapped_end = data.len() - label_length;
            let plaintext = rsa_aes_unwrap(
                &signing_key(wrap_key)?,
                &data[4..wrapped_end],
                modulus_length,
                &data[wrapped_end..],
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
        const HEADER_LENGTH: usize = 58;
        if data.len() < HEADER_LENGTH {
            return Err(DeviceError::WrongLength);
        }
        let object_type = ObjectType::from_byte(data[2]).ok_or(DeviceError::InvalidData)?;
        if !matches!(
            object_type,
            ObjectType::AsymmetricKey | ObjectType::SymmetricKey
        ) {
            return Err(DeviceError::InvalidData);
        }
        let algorithm = Algorithm::from_byte(data[55]).ok_or(DeviceError::InvalidData)?;
        self.require_algorithm_enabled(algorithm as u8)?;
        let label_digest_length = rsa_oaep_hash(data[56])?.output_length();
        let mgf_hash = rsa_mgf_hash(data[57])?;
        let wrap_id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let (material, logical_length) = {
            let wrap_key = self.rsa_private_wrap_key(authorization, wrap_id)?;
            let modulus_length = wrap_key.info.length as usize;
            if data.len() <= HEADER_LENGTH + modulus_length + label_digest_length {
                return Err(DeviceError::WrongLength);
            }
            let wrapped_end = data.len() - label_digest_length;
            let plaintext = rsa_aes_unwrap(
                &signing_key(wrap_key)?,
                &data[HEADER_LENGTH..wrapped_end],
                modulus_length,
                &data[wrapped_end..],
                mgf_hash,
            )?;
            import_rsa_wrapped_key_material(object_type, algorithm, &plaintext)?
        };
        let id = self.resolve_id(
            object_type,
            u16::from_be_bytes(data[3..5].try_into().unwrap()),
        )?;
        let info = ObjectInfo {
            capabilities: CapabilitySet::from_bytes(data[47..55].try_into().unwrap()),
            id,
            length: logical_length
                .try_into()
                .map_err(|_| DeviceError::WrongLength)?,
            domains: u16::from_be_bytes(data[45..47].try_into().unwrap()),
            object_type,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: 0x12,
            label: trim_label(&data[5..45]),
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
        if data.len() < 2 + AES_BLOCK_SIZE || (data.len() - 2) % AES_BLOCK_SIZE != 0 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.symmetric_object(authorization, id)?;
        let key = object_secret(object)?;
        let result = if encrypt {
            encrypt_aes_ecb(key, &data[2..])
        } else {
            decrypt_aes_ecb(key, &data[2..])
        };
        result.map_err(|_| DeviceError::InvalidData)
    }

    fn crypt_aes_cbc(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
        encrypt: bool,
    ) -> Result<Vec<u8>> {
        if data.len() < 2 + AES_BLOCK_SIZE * 2
            || (data.len() - 2 - AES_BLOCK_SIZE) % AES_BLOCK_SIZE != 0
        {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.symmetric_object(authorization, id)?;
        let key = object_secret(object)?;
        let iv = &data[2..2 + AES_BLOCK_SIZE];
        let input = &data[2 + AES_BLOCK_SIZE..];
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
        const HEADER_LENGTH: usize = 57;
        if data.len() < HEADER_LENGTH || (generate && data.len() != HEADER_LENGTH) {
            return Err(DeviceError::WrongLength);
        }
        let algorithm = Algorithm::from_byte(data[52]).ok_or(DeviceError::InvalidData)?;
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
            if data.len() != HEADER_LENGTH + key_length {
                return Err(DeviceError::WrongLength);
            }
            data[HEADER_LENGTH..].to_vec()
        };
        let id = self.resolve_id(
            ObjectType::OtpAeadKey,
            u16::from_be_bytes(data[..2].try_into().unwrap()),
        )?;
        let capability = if generate {
            Capability::GenerateOtpAeadKey
        } else {
            Capability::PutOtpAeadKey
        };
        let info = ObjectInfo {
            capabilities: CapabilitySet::from_bytes(data[44..52].try_into().unwrap()),
            id,
            length: key_length as u16,
            domains: u16::from_be_bytes(data[42..44].try_into().unwrap()),
            object_type: ObjectType::OtpAeadKey,
            algorithm: algorithm as u8,
            sequence: 0,
            origin: if generate { 1 } else { 2 },
            label: trim_label(&data[2..42]),
            delegated_capabilities: CapabilitySet::NONE,
        };
        authorization.authorize_create(&info, capability)?;
        let record = ObjectRecord {
            info,
            material: ObjectMaterial::OtpAeadKey {
                nonce_id: data[53..57].try_into().unwrap(),
                key,
            },
        };
        record.validate()?;
        self.write_object(record)?;
        Ok(id.to_be_bytes().to_vec())
    }

    fn create_otp_aead(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() != 24 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.otp_aead_key(authorization, id)?;
        otp_aead_encrypt(object, &data[2..24])
    }

    fn randomize_otp_aead(
        &self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let id = parse_u16(data)?;
        let object = self.otp_aead_key(authorization, id)?;
        let mut credential = [0; 22];
        getrandom::fill(&mut credential).map_err(|_| DeviceError::StorageFailed)?;
        otp_aead_encrypt(object, &credential)
    }

    fn decrypt_otp(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() != 54 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.otp_aead_key(authorization, id)?;
        let credential = otp_aead_decrypt(object, &data[2..38])?;
        let token = decrypt_aes_ecb(&credential[..16], &data[38..54])
            .map_err(|_| DeviceError::InvalidData)?;
        if token[..6] != credential[16..22] || yubico_crc16(&token) != 0xf0b8 {
            return Err(DeviceError::InvalidOtp);
        }
        Ok([&token[6..8], &token[11..12], &token[10..11], &token[8..10]].concat())
    }

    fn rewrap_otp_aead(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() != 40 {
            return Err(DeviceError::WrongLength);
        }
        let from = self.otp_aead_key(
            authorization,
            u16::from_be_bytes(data[..2].try_into().unwrap()),
        )?;
        let to = self.otp_aead_key(
            authorization,
            u16::from_be_bytes(data[2..4].try_into().unwrap()),
        )?;
        otp_aead_encrypt(to, &otp_aead_decrypt(from, &data[4..])?)
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
        const HEADER_LENGTH: usize = 53;
        if data.len() <= HEADER_LENGTH {
            return Err(DeviceError::WrongLength);
        }
        if data[52] != Algorithm::TemplateSsh as u8 {
            return Err(DeviceError::InvalidData);
        }
        self.require_algorithm_enabled(data[52])?;
        let material = data[HEADER_LENGTH..].to_vec();
        let id = self.resolve_id(
            ObjectType::Template,
            u16::from_be_bytes(data[..2].try_into().unwrap()),
        )?;
        let info = ObjectInfo {
            capabilities: CapabilitySet::from_bytes(data[44..52].try_into().unwrap()),
            id,
            length: material
                .len()
                .try_into()
                .map_err(|_| DeviceError::WrongLength)?,
            domains: u16::from_be_bytes(data[42..44].try_into().unwrap()),
            object_type: ObjectType::Template,
            algorithm: data[52],
            sequence: 0,
            origin: 2,
            label: trim_label(&data[2..42]),
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
        let id = parse_u16(data)?;
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
        if data.len() < 2 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.hmac_object(authorization, id)?;
        calculate_hmac(object, &data[2..])
    }

    fn verify_hmac(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 2 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.hmac_object(authorization, id)?;
        let signature_length = hmac_length(object.info.algorithm)?;
        if data.len() < 2 + signature_length {
            return Err(DeviceError::WrongLength);
        }
        let expected = calculate_hmac(object, &data[2 + signature_length..])?;
        Ok(vec![u8::from(bool::from(
            expected.as_slice().ct_eq(&data[2..2 + signature_length]),
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
        if data.len() < 3 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let algorithm = data[2];
        self.require_algorithm_enabled(algorithm)?;
        let key_length = authentication_key_length(algorithm)?;
        if data.len() != 3 + key_length {
            return Err(DeviceError::WrongLength);
        }
        let key = ObjectKey {
            object_type: ObjectType::AuthenticationKey,
            id,
        };
        let material = parse_authentication_key_material(algorithm, &data[3..])?;
        let mut updated = self
            .objects
            .get(&key)
            .cloned()
            .ok_or(DeviceError::ObjectNotFound)?;
        updated.info.algorithm = algorithm;
        updated.info.length = key_length as u16;
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
                length: 32,
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

fn asymmetric_key_algorithm(algorithm: u8) -> Result<(SoftwareSigningAlgorithm, usize)> {
    match algorithm {
        47 => Ok((SoftwareSigningAlgorithm::EcdsaP224Sha224, 28)),
        12 => Ok((SoftwareSigningAlgorithm::EcdsaP256Sha256, 32)),
        13 => Ok((SoftwareSigningAlgorithm::EcdsaP384Sha384, 48)),
        14 => Ok((SoftwareSigningAlgorithm::EcdsaP521Sha512, 66)),
        15 => Ok((SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256, 32)),
        16 => Ok((SoftwareSigningAlgorithm::EcdsaBrainpoolP256Sha256, 32)),
        17 => Ok((SoftwareSigningAlgorithm::EcdsaBrainpoolP384Sha384, 48)),
        18 => Ok((SoftwareSigningAlgorithm::EcdsaBrainpoolP512Sha512, 64)),
        46 => Ok((SoftwareSigningAlgorithm::Ed25519, 32)),
        _ => Err(DeviceError::InvalidData),
    }
}

fn asymmetric_key_material(
    algorithm: Algorithm,
    generate: bool,
    supplied: &[u8],
) -> Result<Vec<u8>> {
    let expected_length = algorithm
        .asymmetric_key_length()
        .ok_or(DeviceError::InvalidData)?;
    if generate && !supplied.is_empty() {
        return Err(DeviceError::WrongLength);
    }
    if algorithm == Algorithm::X25519 {
        let key = if generate {
            SoftwareX25519Key::generate().map_err(|_| DeviceError::StorageFailed)?
        } else {
            if supplied.len() != expected_length {
                return Err(DeviceError::WrongLength);
            }
            SoftwareX25519Key::from_serialized(supplied).map_err(|_| DeviceError::InvalidData)?
        };
        return Ok(key.serialized().to_vec());
    }
    if algorithm.is_rsa_key() {
        let key = if generate {
            SoftwareSigningKey::generate_rsa(expected_length * 8)
                .map_err(|_| DeviceError::StorageFailed)?
        } else {
            if supplied.len() != expected_length {
                return Err(DeviceError::WrongLength);
            }
            let (p, q) = supplied.split_at(expected_length / 2);
            SoftwareSigningKey::from_rsa_primes(p, q, &[1, 0, 1])
                .map_err(|_| DeviceError::InvalidData)?
        };
        let [p, q, _, _, _] = key
            .rsa_crt_components()
            .map_err(|_| DeviceError::InvalidData)?;
        let component_length = expected_length / 2;
        let mut encoded = left_pad_component(&p, component_length)?;
        encoded.extend_from_slice(&left_pad_component(&q, component_length)?);
        return Ok(encoded);
    }
    let (software_algorithm, _) = asymmetric_key_algorithm(algorithm as u8)?;
    let key = if generate {
        SoftwareSigningKey::generate(software_algorithm).map_err(|_| DeviceError::StorageFailed)?
    } else {
        if supplied.len() != expected_length {
            return Err(DeviceError::WrongLength);
        }
        SoftwareSigningKey::from_serialized(software_algorithm, supplied)
            .map_err(|_| DeviceError::InvalidData)?
    };
    let secret = key
        .serialized()
        .map_err(|_| DeviceError::InvalidData)?
        .to_vec();
    if secret.len() != expected_length {
        return Err(DeviceError::InvalidData);
    }
    Ok(secret)
}

fn import_rsa_wrapped_key_material(
    object_type: ObjectType,
    algorithm: Algorithm,
    plaintext: &[u8],
) -> Result<(ObjectMaterial, usize)> {
    match object_type {
        ObjectType::AsymmetricKey => {
            if algorithm == Algorithm::X25519 {
                return Err(DeviceError::InvalidData);
            }
            let (software_algorithm, _) = if algorithm.is_rsa_key() {
                (SoftwareSigningAlgorithm::RsaPssSha256, 0)
            } else {
                asymmetric_key_algorithm(algorithm as u8)?
            };
            let key = SoftwareSigningKey::from_pkcs8_der(software_algorithm, plaintext)
                .map_err(|_| DeviceError::InvalidData)?;
            let material = if algorithm.is_rsa_key() {
                let [p, q, _, _, _] = key
                    .rsa_crt_components()
                    .map_err(|_| DeviceError::InvalidData)?;
                let logical_length = algorithm.asymmetric_key_length().unwrap();
                let component_length = logical_length / 2;
                let mut encoded = left_pad_component(&p, component_length)?;
                encoded.extend_from_slice(&left_pad_component(&q, component_length)?);
                encoded
            } else {
                key.serialized()
                    .map_err(|_| DeviceError::InvalidData)?
                    .to_vec()
            };
            let logical_length = algorithm
                .asymmetric_key_length()
                .ok_or(DeviceError::InvalidData)?;
            if material.len() != logical_length {
                return Err(DeviceError::InvalidData);
            }
            Ok((ObjectMaterial::Secret(material), logical_length))
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

fn left_pad_component(component: &[u8], length: usize) -> Result<Vec<u8>> {
    if component.len() > length {
        return Err(DeviceError::InvalidData);
    }
    let mut padded = vec![0; length];
    padded[length - component.len()..].copy_from_slice(component);
    Ok(padded)
}

fn signing_key(object: &ObjectRecord) -> Result<SoftwareSigningKey> {
    let ObjectMaterial::Secret(secret) = &object.material else {
        return Err(DeviceError::InvalidData);
    };
    let algorithm = Algorithm::from_byte(object.info.algorithm).ok_or(DeviceError::InvalidData)?;
    if algorithm.is_rsa_key() {
        if secret.len() != object.info.length as usize || secret.len() % 2 != 0 {
            return Err(DeviceError::InvalidData);
        }
        let (p, q) = secret.split_at(secret.len() / 2);
        return SoftwareSigningKey::from_rsa_primes(p, q, &[1, 0, 1])
            .map_err(|_| DeviceError::InvalidData);
    }
    let (algorithm, _) = asymmetric_key_algorithm(object.info.algorithm)?;
    SoftwareSigningKey::from_serialized(algorithm, secret).map_err(|_| DeviceError::InvalidData)
}

fn object_subject_public_key_info(object: &ObjectRecord) -> Result<SubjectPublicKeyInfoOwned> {
    if object.info.algorithm == Algorithm::X25519 as u8 {
        return Ok(SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.3.101.110"),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&x25519_key(object)?.public_key())
                .map_err(|_| DeviceError::InvalidData)?,
        });
    }
    match signing_key(object)?.public_key() {
        SoftwarePublicKey::Ec {
            curve,
            uncompressed,
        } => ec_subject_public_key_info(curve, &uncompressed),
        SoftwarePublicKey::Ed25519(public) => Ok(SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.3.101.112"),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&public)
                .map_err(|_| DeviceError::InvalidData)?,
        }),
        SoftwarePublicKey::Rsa { modulus, exponent } => {
            let public = RsaPublicKey::new(
                BigUint::from_bytes_be(&modulus),
                BigUint::from_bytes_be(&exponent),
            )
            .map_err(|_| DeviceError::InvalidData)?;
            let encoded = public
                .to_public_key_der()
                .map_err(|_| DeviceError::InvalidData)?;
            SubjectPublicKeyInfoOwned::from_der(encoded.as_bytes())
                .map_err(|_| DeviceError::InvalidData)
        }
        SoftwarePublicKey::MlDsa { .. } => Err(DeviceError::InvalidData),
    }
}

fn ec_subject_public_key_info(
    curve: EcCurve,
    uncompressed: &[u8],
) -> Result<SubjectPublicKeyInfoOwned> {
    let curve_oid = match curve {
        EcCurve::P224 => "1.3.132.0.33",
        EcCurve::P256 => "1.2.840.10045.3.1.7",
        EcCurve::P384 => "1.3.132.0.34",
        EcCurve::P521 => "1.3.132.0.35",
        EcCurve::Secp256k1 => "1.3.132.0.10",
        EcCurve::BrainpoolP256 => "1.3.36.3.3.2.8.1.1.7",
        EcCurve::BrainpoolP384 => "1.3.36.3.3.2.8.1.1.11",
        EcCurve::BrainpoolP512 => "1.3.36.3.3.2.8.1.1.13",
    };
    let curve_oid = ObjectIdentifier::new(curve_oid).map_err(|_| DeviceError::InvalidData)?;
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
            parameters: Some(Any::encode_from(&curve_oid).map_err(|_| DeviceError::InvalidData)?),
        },
        subject_public_key: BitString::from_bytes(uncompressed)
            .map_err(|_| DeviceError::InvalidData)?,
    })
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

fn rsa_key(object: &ObjectRecord) -> Result<SoftwareSigningKey> {
    let algorithm = Algorithm::from_byte(object.info.algorithm).ok_or(DeviceError::InvalidData)?;
    if !algorithm.is_rsa_key() {
        return Err(DeviceError::InvalidData);
    }
    signing_key(object)
}

fn x25519_key(object: &ObjectRecord) -> Result<SoftwareX25519Key> {
    if object.info.algorithm != Algorithm::X25519 as u8 {
        return Err(DeviceError::InvalidData);
    }
    let ObjectMaterial::Secret(secret) = &object.material else {
        return Err(DeviceError::InvalidData);
    };
    SoftwareX25519Key::from_serialized(secret).map_err(|_| DeviceError::InvalidData)
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

fn encode_wrapped_object(object: &ObjectRecord) -> Result<Vec<u8>> {
    let (material_kind, payload) = match &object.material {
        ObjectMaterial::Secret(value) => (0, value.clone()),
        ObjectMaterial::Opaque(value) => (1, value.clone()),
        ObjectMaterial::Public(value) => (2, value.clone()),
        ObjectMaterial::Authentication(AuthenticationKeyMaterial::Symmetric(value)) => {
            (3, value.clone())
        }
        ObjectMaterial::Authentication(AuthenticationKeyMaterial::Asymmetric(value)) => {
            (4, value.clone())
        }
        ObjectMaterial::OtpAeadKey { nonce_id, key } => {
            (5, [nonce_id.as_slice(), key.as_slice()].concat())
        }
    };
    let payload_length: u16 = payload
        .len()
        .try_into()
        .map_err(|_| DeviceError::WrongLength)?;
    let mut output = Vec::with_capacity(71 + payload.len());
    output.extend_from_slice(b"VYH1");
    output.push(object.info.object_type as u8);
    output.extend_from_slice(&object.info.id.to_be_bytes());
    output.extend_from_slice(&object.info.domains.to_be_bytes());
    output.extend_from_slice(&object.info.capabilities.to_bytes());
    output.push(object.info.algorithm);
    output.push(object.info.origin & 0x0f);
    let mut label = [0; 40];
    label[..object.info.label.len()].copy_from_slice(&object.info.label);
    output.extend_from_slice(&label);
    output.extend_from_slice(&object.info.delegated_capabilities.to_bytes());
    output.push(material_kind);
    output.extend_from_slice(&payload_length.to_be_bytes());
    output.extend_from_slice(&payload);
    Ok(output)
}

fn decode_wrapped_object(mut data: &[u8]) -> Result<ObjectRecord> {
    let version = take(&mut data, 4)?;
    if version != b"VYH1" {
        return Err(DeviceError::InvalidData);
    }
    let object_type =
        ObjectType::from_byte(take(&mut data, 1)?[0]).ok_or(DeviceError::InvalidData)?;
    let id = u16::from_be_bytes(take(&mut data, 2)?.try_into().unwrap());
    let domains = u16::from_be_bytes(take(&mut data, 2)?.try_into().unwrap());
    let capabilities = CapabilitySet::from_bytes(take(&mut data, 8)?.try_into().unwrap());
    let algorithm = take(&mut data, 1)?[0];
    let origin = take(&mut data, 1)?[0] & 0x0f;
    let label = trim_label(take(&mut data, 40)?);
    let delegated_capabilities = CapabilitySet::from_bytes(take(&mut data, 8)?.try_into().unwrap());
    let material_kind = take(&mut data, 1)?[0];
    let payload_length = u16::from_be_bytes(take(&mut data, 2)?.try_into().unwrap()) as usize;
    let payload = take(&mut data, payload_length)?;
    if !data.is_empty() {
        return Err(DeviceError::WrongLength);
    }
    let material = match material_kind {
        0 => ObjectMaterial::Secret(payload.to_vec()),
        1 => ObjectMaterial::Opaque(payload.to_vec()),
        2 => ObjectMaterial::Public(payload.to_vec()),
        3 => ObjectMaterial::Authentication(AuthenticationKeyMaterial::Symmetric(payload.to_vec())),
        4 => {
            ObjectMaterial::Authentication(AuthenticationKeyMaterial::Asymmetric(payload.to_vec()))
        }
        5 if payload.len() >= 4 => ObjectMaterial::OtpAeadKey {
            nonce_id: payload[..4].try_into().unwrap(),
            key: payload[4..].to_vec(),
        },
        _ => return Err(DeviceError::InvalidData),
    };
    let record = ObjectRecord {
        info: ObjectInfo {
            capabilities,
            id,
            length: material.len() as u16,
            domains,
            object_type,
            algorithm,
            sequence: 0,
            origin,
            label,
            delegated_capabilities,
        },
        material,
    };
    record.validate()?;
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
    if object.info.algorithm == Algorithm::X25519 as u8 {
        x25519_key(object)?
            .derive(peer_public)
            .map_err(|_| DeviceError::InvalidData)
    } else {
        derive_with_signing_key(&signing_key(object)?, peer_public)
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

fn parse_u16(data: &[u8]) -> Result<u16> {
    data.try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| DeviceError::WrongLength)
}

fn parse_u16_at(data: &[u8], offset: usize) -> Result<u16> {
    data.get(offset..offset + 2)
        .ok_or(DeviceError::WrongLength)?
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| DeviceError::WrongLength)
}

fn parse_object_key(data: &[u8]) -> Result<ObjectKey> {
    if data.len() != 3 {
        return Err(DeviceError::WrongLength);
    }
    Ok(ObjectKey {
        id: u16::from_be_bytes(data[..2].try_into().unwrap()),
        object_type: ObjectType::from_byte(data[2]).ok_or(DeviceError::InvalidData)?,
    })
}

fn require_empty(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(DeviceError::WrongLength)
    }
}

fn trim_label(label: &[u8]) -> Vec<u8> {
    label
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default()
        .to_vec()
}

#[derive(Default)]
struct ObjectFilters {
    id: Option<u16>,
    object_type: Option<ObjectType>,
    domains: Option<u16>,
    capabilities: Option<CapabilitySet>,
    algorithm: Option<u8>,
    label: Option<Vec<u8>>,
}

impl ObjectFilters {
    fn parse(mut encoded: &[u8]) -> Result<Self> {
        let mut filters = Self::default();
        while let Some((&tag, tail)) = encoded.split_first() {
            encoded = tail;
            match tag {
                1 => {
                    filters.id = Some(read_filter_u16(&mut encoded)?);
                }
                2 => {
                    filters.object_type = Some(
                        ObjectType::from_byte(take(&mut encoded, 1)?[0])
                            .ok_or(DeviceError::InvalidData)?,
                    );
                }
                3 => filters.domains = Some(read_filter_u16(&mut encoded)?),
                4 => {
                    filters.capabilities = Some(CapabilitySet::from_bytes(
                        take(&mut encoded, 8)?.try_into().unwrap(),
                    ));
                }
                5 => filters.algorithm = Some(take(&mut encoded, 1)?[0]),
                6 => filters.label = Some(trim_label(take(&mut encoded, 40)?)),
                _ => return Err(DeviceError::InvalidData),
            }
        }
        Ok(filters)
    }

    fn matches(&self, object: &ObjectInfo) -> bool {
        self.id.is_none_or(|id| object.id == id)
            && self
                .object_type
                .is_none_or(|object_type| object.object_type == object_type)
            && self
                .domains
                .is_none_or(|domains| object.domains & domains != 0)
            && self
                .capabilities
                .is_none_or(|capabilities| object.capabilities.contains_all(capabilities))
            && self
                .algorithm
                .is_none_or(|algorithm| object.algorithm == algorithm)
            && self
                .label
                .as_ref()
                .is_none_or(|label| &object.label == label)
    }
}

fn take<'a>(data: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    if data.len() < length {
        return Err(DeviceError::WrongLength);
    }
    let (value, tail) = data.split_at(length);
    *data = tail;
    Ok(value)
}

fn read_filter_u16(data: &mut &[u8]) -> Result<u16> {
    Ok(u16::from_be_bytes(take(data, 2)?.try_into().unwrap()))
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
    let first = data
        .get(..2)
        .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()))
        .unwrap_or(0);
    match command {
        CommandCode::SignAttestationCertificate | CommandCode::RewrapOtpAead => {
            let second = data
                .get(2..4)
                .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()))
                .unwrap_or(0);
            (first, second)
        }
        CommandCode::ExportWrapped | CommandCode::ExportRsaWrapped => {
            let target = data
                .get(3..5)
                .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()))
                .unwrap_or(0);
            (target, first)
        }
        _ => (first, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_channel_crypto::{
        cbc_decrypt, cbc_encrypt, cmac, encrypt_block, pad, scp03_kdf, unpad, BLOCK_SIZE,
    };
    use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
    use software_key_core::software_signing::EcCurve;

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

    fn put_wrap_key_request(
        id: u16,
        algorithm: Algorithm,
        capabilities: CapabilitySet,
        delegated_capabilities: CapabilitySet,
        key: &[u8],
    ) -> Frame {
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(b"wrap key");
        data.resize(42, 0);
        data.extend_from_slice(&1_u16.to_be_bytes());
        data.extend_from_slice(&capabilities.to_bytes());
        data.push(algorithm as u8);
        data.extend_from_slice(&delegated_capabilities.to_bytes());
        data.extend_from_slice(key);
        Frame::new(CommandCode::PutWrapKey as u8, data).unwrap()
    }

    fn put_otp_aead_key_request(
        id: u16,
        capabilities: CapabilitySet,
        algorithm: Algorithm,
        nonce_id: u32,
        key: &[u8],
    ) -> Frame {
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(b"OTP AEAD key");
        data.resize(42, 0);
        data.extend_from_slice(&1_u16.to_be_bytes());
        data.extend_from_slice(&capabilities.to_bytes());
        data.push(algorithm as u8);
        data.extend_from_slice(&nonce_id.to_le_bytes());
        data.extend_from_slice(key);
        Frame::new(CommandCode::PutOtpAeadKey as u8, data).unwrap()
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
            Frame::new(CommandCode::GetPseudoRandom as u8, 3_116_u16.to_be_bytes()).unwrap();
        assert_eq!(
            device.execute_inner(authorization, &maximum).data.len(),
            3_116
        );

        let oversized =
            Frame::new(CommandCode::GetPseudoRandom as u8, 3_117_u16.to_be_bytes()).unwrap();
        assert_eq!(
            device.execute_inner(authorization, &oversized),
            Frame::error(DeviceError::WrongLength)
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
    fn opaque_read_requires_get_opaque_on_session_and_object() {
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
            device.execute_inner(with_get_opaque, &get_without_object_capability),
            Frame::error(DeviceError::InsufficientPermissions)
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
        assert!(device
            .objects
            .keys()
            .all(|key| key.id != 0 && key.id != u16::MAX));
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
        let response = Frame::parse(&device.handle_encoded(&message.encode())).unwrap();
        assert_eq!(response.command, CommandCode::SessionMessage as u8 | 0x80);

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
        assert_eq!(signature.data.len(), 64);
        public
            .verify_prehash(
                SoftwareSigningAlgorithm::EcdsaP256Sha256,
                &digest,
                &signature.data,
            )
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
            .verify_prehash(
                SoftwareSigningAlgorithm::RsaPkcs1Sha256,
                &digest,
                &signature.data,
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
    fn x25519_extension_generates_exports_and_derives_raw_shared_secrets() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let capabilities = CapabilitySet::from_capabilities([Capability::DeriveEcdh]);
        for id in [44, 45] {
            let request =
                generate_asymmetric_key_request(id, 1, capabilities, Algorithm::X25519 as u8);
            assert_eq!(device.execute_inner(admin, &request).data, id.to_be_bytes());
        }
        let public = |device: &mut Device, id: u16| {
            let request = Frame::new(CommandCode::GetPublicKey as u8, id.to_be_bytes()).unwrap();
            let response = device.execute_inner(admin, &request);
            assert_eq!(response.data[0], Algorithm::X25519 as u8);
            response.data[1..].to_vec()
        };
        let first_public = public(&mut device, 44);
        let second_public = public(&mut device, 45);
        let derive = |device: &mut Device, id: u16, peer: &[u8]| {
            let request = Frame::new(
                CommandCode::DeriveEcdh as u8,
                [id.to_be_bytes().as_slice(), peer].concat(),
            )
            .unwrap();
            device.execute_inner(admin, &request).data
        };
        assert_eq!(
            derive(&mut device, 44, &second_public),
            derive(&mut device, 45, &first_public)
        );
    }

    #[test]
    fn prefixed_ecdh_kdf_derives_without_exposing_the_raw_secret() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let capabilities = CapabilitySet::from_capabilities([Capability::DeriveEcdhKdf]);
        for id in [46, 47] {
            let request =
                generate_asymmetric_key_request(id, 1, capabilities, Algorithm::EcP256 as u8);
            assert_eq!(device.execute_inner(admin, &request).data, id.to_be_bytes());
        }
        let public = |device: &mut Device, id: u16| {
            let request = Frame::new(CommandCode::GetPublicKey as u8, id.to_be_bytes()).unwrap();
            let response = device.execute_inner(admin, &request);
            assert_eq!(response.data[0], Algorithm::EcP256 as u8);
            [&[0x04], &response.data[1..]].concat()
        };
        let peer_public = public(&mut device, 47);
        let object = device
            .object(ObjectKey {
                object_type: ObjectType::AsymmetricKey,
                id: 46,
            })
            .unwrap();
        let raw_secret = raw_ecdh_secret(object, &peer_public).unwrap();
        let prepend = [0x41; 32];
        let shared_info = [0x3c, 0x88, 0x10];
        let mut prefixed = Zeroizing::new(Vec::new());
        prefixed.extend_from_slice(&prepend);
        prefixed.extend_from_slice(&raw_secret);
        let expected = x963_kdf(HashAlgorithm::Sha256, &prefixed, &shared_info, 64).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(&46_u16.to_be_bytes());
        data.push(3); // X9.63 SHA-256
        data.extend_from_slice(&64_u16.to_be_bytes());
        for value in [peer_public.len(), prepend.len(), shared_info.len()] {
            data.extend_from_slice(&u16::try_from(value).unwrap().to_be_bytes());
        }
        data.extend_from_slice(&peer_public);
        data.extend_from_slice(&prepend);
        data.extend_from_slice(&shared_info);
        let request = Frame::new(CommandCode::DeriveEcdhKdf as u8, data).unwrap();
        assert_eq!(device.execute_inner(admin, &request).data, *expected);

        let raw_request = Frame::new(
            CommandCode::DeriveEcdh as u8,
            [46_u16.to_be_bytes().as_slice(), peer_public.as_slice()].concat(),
        )
        .unwrap();
        assert_eq!(
            device.execute_inner(admin, &raw_request),
            Frame::error(DeviceError::InsufficientPermissions)
        );

        // Empty augmentation still passes the secret through a mandatory KDF;
        // there is no CKD_NULL equivalent that can disclose the raw result.
        let mut data = Vec::new();
        data.extend_from_slice(&46_u16.to_be_bytes());
        data.push(3);
        data.extend_from_slice(&32_u16.to_be_bytes());
        data.extend_from_slice(&u16::try_from(peer_public.len()).unwrap().to_be_bytes());
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&peer_public);
        let request = Frame::new(CommandCode::DeriveEcdhKdf as u8, data).unwrap();
        let derived = device.execute_inner(admin, &request).data;
        assert_eq!(derived.len(), raw_secret.len());
        assert_ne!(derived, *raw_secret);
    }

    #[test]
    fn every_official_ec_key_algorithm_is_available_through_device_commands() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let capabilities =
            CapabilitySet::from_capabilities([Capability::SignEcdsa, Capability::DeriveEcdh]);
        for (id, algorithm, coordinate_length) in [
            (80, Algorithm::EcP224, 28),
            (81, Algorithm::EcP256, 32),
            (82, Algorithm::EcP384, 48),
            (83, Algorithm::EcP521, 66),
            (84, Algorithm::EcK256, 32),
            (85, Algorithm::EcBrainpoolP256, 32),
            (86, Algorithm::EcBrainpoolP384, 48),
            (87, Algorithm::EcBrainpoolP512, 64),
        ] {
            let generate = generate_asymmetric_key_request(id, 1, capabilities, algorithm as u8);
            assert_eq!(
                device.execute_inner(admin, &generate).data,
                id.to_be_bytes()
            );
            let public = Frame::new(CommandCode::GetPublicKey as u8, id.to_be_bytes()).unwrap();
            let public = device.execute_inner(admin, &public).data;
            assert_eq!(public[0], algorithm as u8);
            assert_eq!(public.len(), 1 + coordinate_length * 2);
            let sign = Frame::new(
                CommandCode::SignEcdsa as u8,
                [id.to_be_bytes().as_slice(), &[0x5a; 64]].concat(),
            )
            .unwrap();
            assert_eq!(
                device.execute_inner(admin, &sign).data.len(),
                coordinate_length * 2
            );
        }
    }

    #[test]
    fn symmetric_key_commands_cover_aes_128_192_and_256_ecb_and_cbc() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let capabilities = CapabilitySet::from_capabilities([
            Capability::EncryptEcb,
            Capability::DecryptEcb,
            Capability::EncryptCbc,
            Capability::DecryptCbc,
        ]);
        let plaintext = [0x5a; AES_BLOCK_SIZE * 2];
        let iv = [0xa5; AES_BLOCK_SIZE];
        for (id, algorithm, key_length) in [
            (50, Algorithm::Aes128, 16),
            (51, Algorithm::Aes192, 24),
            (52, Algorithm::Aes256, 32),
        ] {
            let key = vec![id as u8; key_length];
            let put = put_symmetric_key_request(id, 1, capabilities, algorithm, &key);
            assert_eq!(device.execute_inner(admin, &put).data, id.to_be_bytes());

            let ecb_encrypt = Frame::new(
                CommandCode::EncryptEcb as u8,
                [id.to_be_bytes().as_slice(), plaintext.as_slice()].concat(),
            )
            .unwrap();
            let ciphertext = device.execute_inner(admin, &ecb_encrypt).data;
            assert_ne!(ciphertext, plaintext);
            let ecb_decrypt = Frame::new(
                CommandCode::DecryptEcb as u8,
                [id.to_be_bytes().as_slice(), ciphertext.as_slice()].concat(),
            )
            .unwrap();
            assert_eq!(device.execute_inner(admin, &ecb_decrypt).data, plaintext);

            let cbc_encrypt = Frame::new(
                CommandCode::EncryptCbc as u8,
                [
                    id.to_be_bytes().as_slice(),
                    iv.as_slice(),
                    plaintext.as_slice(),
                ]
                .concat(),
            )
            .unwrap();
            let ciphertext = device.execute_inner(admin, &cbc_encrypt).data;
            let cbc_decrypt = Frame::new(
                CommandCode::DecryptCbc as u8,
                [
                    id.to_be_bytes().as_slice(),
                    iv.as_slice(),
                    ciphertext.as_slice(),
                ]
                .concat(),
            )
            .unwrap();
            assert_eq!(device.execute_inner(admin, &cbc_decrypt).data, plaintext);
        }
    }

    #[test]
    fn aes_ccm_wrap_data_uses_version_nonce_ciphertext_and_tag() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let capabilities =
            CapabilitySet::from_capabilities([Capability::WrapData, Capability::UnwrapData]);
        for (id, algorithm, key_length) in [
            (60, Algorithm::Aes128CcmWrap, 16),
            (61, Algorithm::Aes192CcmWrap, 24),
            (62, Algorithm::Aes256CcmWrap, 32),
        ] {
            let put = put_wrap_key_request(
                id,
                algorithm,
                capabilities,
                CapabilitySet::NONE,
                &vec![id as u8; key_length],
            );
            assert_eq!(device.execute_inner(admin, &put).data, id.to_be_bytes());
            let plaintext = b"arbitrary authenticated data";
            let wrap = Frame::new(
                CommandCode::WrapData as u8,
                [id.to_be_bytes().as_slice(), plaintext.as_slice()].concat(),
            )
            .unwrap();
            let wrapped = device.execute_inner(admin, &wrap).data;
            assert_eq!(wrapped[0], 1);
            assert_eq!(wrapped.len(), plaintext.len() + 1 + 13 + 16);
            let unwrap = Frame::new(
                CommandCode::UnwrapData as u8,
                [id.to_be_bytes().as_slice(), wrapped.as_slice()].concat(),
            )
            .unwrap();
            assert_eq!(device.execute_inner(admin, &unwrap).data, plaintext);

            let mut tampered = wrapped;
            *tampered.last_mut().unwrap() ^= 1;
            let unwrap = Frame::new(
                CommandCode::UnwrapData as u8,
                [id.to_be_bytes().as_slice(), tampered.as_slice()].concat(),
            )
            .unwrap();
            assert_eq!(
                device.execute_inner(admin, &unwrap),
                Frame::error(DeviceError::InvalidData)
            );
        }
    }

    #[test]
    fn wrapped_object_round_trip_preserves_policy_and_material() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let target_capabilities = CapabilitySet::from_capabilities([
            Capability::GetOpaque,
            Capability::DeleteOpaque,
            Capability::ExportableUnderWrap,
        ]);
        let wrap_capabilities = CapabilitySet::from_capabilities([
            Capability::ExportWrapped,
            Capability::ImportWrapped,
        ]);
        let put_wrap = put_wrap_key_request(
            65,
            Algorithm::Aes256CcmWrap,
            wrap_capabilities,
            target_capabilities,
            &[0x65; 32],
        );
        assert_eq!(
            device.execute_inner(admin, &put_wrap).data,
            65_u16.to_be_bytes()
        );
        let put_target = put_opaque_request(66, 1, target_capabilities);
        assert_eq!(
            device.execute_inner(admin, &put_target).data,
            66_u16.to_be_bytes()
        );

        let export = Frame::new(
            CommandCode::ExportWrapped as u8,
            [
                65_u16.to_be_bytes().as_slice(),
                &[ObjectType::Opaque as u8],
                66_u16.to_be_bytes().as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        let wrapped = device.execute_inner(admin, &export).data;
        let delete = Frame::new(
            CommandCode::DeleteObject as u8,
            [66_u16.to_be_bytes().as_slice(), &[ObjectType::Opaque as u8]].concat(),
        )
        .unwrap();
        assert!(device.execute_inner(admin, &delete).data.is_empty());

        let import = Frame::new(
            CommandCode::ImportWrapped as u8,
            [65_u16.to_be_bytes().as_slice(), wrapped.as_slice()].concat(),
        )
        .unwrap();
        assert_eq!(
            device.execute_inner(admin, &import).data,
            [ObjectType::Opaque as u8, 0, 66]
        );
        let restored = device
            .object(ObjectKey {
                object_type: ObjectType::Opaque,
                id: 66,
            })
            .unwrap();
        assert_eq!(restored.info.origin, 0x12);
        assert_eq!(restored.info.capabilities, target_capabilities);
        assert_eq!(
            restored.material,
            ObjectMaterial::Opaque(b"payload".to_vec())
        );
    }

    #[test]
    fn rsa_aes_key_wrap_round_trip_uses_oaep_and_aes_kwp() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let opaque_capabilities = CapabilitySet::from_capabilities([
            Capability::GetOpaque,
            Capability::DeleteOpaque,
            Capability::ExportableUnderWrap,
        ]);
        let delegated_capabilities = CapabilitySet::from_capabilities([
            Capability::GetOpaque,
            Capability::DeleteOpaque,
            Capability::DeleteAsymmetricKey,
            Capability::SignEcdsa,
            Capability::ExportableUnderWrap,
        ]);

        let mut generate_private = Vec::new();
        generate_private.extend_from_slice(&90_u16.to_be_bytes());
        generate_private.extend_from_slice(b"RSA private wrap");
        generate_private.resize(42, 0);
        generate_private.extend_from_slice(&1_u16.to_be_bytes());
        generate_private.extend_from_slice(
            &CapabilitySet::from_capabilities([Capability::ImportWrapped]).to_bytes(),
        );
        generate_private.push(Algorithm::Rsa2048 as u8);
        generate_private.extend_from_slice(&delegated_capabilities.to_bytes());
        let generate_private =
            Frame::new(CommandCode::GenerateWrapKey as u8, generate_private).unwrap();
        assert_eq!(
            device.execute_inner(admin, &generate_private).data,
            90_u16.to_be_bytes()
        );

        let private_public = Frame::new(
            CommandCode::GetPublicKey as u8,
            [
                90_u16.to_be_bytes().as_slice(),
                &[ObjectType::WrapKey as u8],
            ]
            .concat(),
        )
        .unwrap();
        let private_public = device.execute_inner(admin, &private_public).data;
        assert_eq!(private_public[0], Algorithm::Rsa2048 as u8);
        let mut put_public = Vec::new();
        put_public.extend_from_slice(&91_u16.to_be_bytes());
        put_public.extend_from_slice(b"RSA public wrap");
        put_public.resize(42, 0);
        put_public.extend_from_slice(&1_u16.to_be_bytes());
        put_public.extend_from_slice(
            &CapabilitySet::from_capabilities([Capability::ExportWrapped]).to_bytes(),
        );
        put_public.push(Algorithm::Rsa2048 as u8);
        put_public.extend_from_slice(&delegated_capabilities.to_bytes());
        put_public.extend_from_slice(&private_public[1..]);
        let put_public = Frame::new(CommandCode::PutPublicWrapKey as u8, put_public).unwrap();
        assert_eq!(
            device.execute_inner(admin, &put_public).data,
            91_u16.to_be_bytes()
        );

        assert_eq!(
            device
                .execute_inner(admin, &put_opaque_request(92, 1, opaque_capabilities))
                .data,
            92_u16.to_be_bytes()
        );
        let label_digest = RsaHashAlgorithm::Sha256.digest(b"hybrid wrap label");
        let export = Frame::new(
            CommandCode::ExportRsaWrapped as u8,
            [
                91_u16.to_be_bytes().as_slice(),
                &[ObjectType::Opaque as u8],
                92_u16.to_be_bytes().as_slice(),
                &[
                    Algorithm::Aes256 as u8,
                    Algorithm::RsaOaepSha256 as u8,
                    Algorithm::Mgf1Sha384 as u8,
                ],
                label_digest.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        let wrapped = device.execute_inner(admin, &export).data;
        assert!(wrapped.len() > 256);

        let delete = Frame::new(
            CommandCode::DeleteObject as u8,
            [92_u16.to_be_bytes().as_slice(), &[ObjectType::Opaque as u8]].concat(),
        )
        .unwrap();
        assert!(device.execute_inner(admin, &delete).data.is_empty());
        let import = Frame::new(
            CommandCode::ImportRsaWrapped as u8,
            [
                90_u16.to_be_bytes().as_slice(),
                &[Algorithm::RsaOaepSha256 as u8, Algorithm::Mgf1Sha384 as u8],
                wrapped.as_slice(),
                label_digest.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        assert_eq!(
            device.execute_inner(admin, &import).data,
            [ObjectType::Opaque as u8, 0, 92]
        );

        let ec_capabilities = CapabilitySet::from_capabilities([
            Capability::DeleteAsymmetricKey,
            Capability::SignEcdsa,
            Capability::ExportableUnderWrap,
        ]);
        let generate =
            generate_asymmetric_key_request(93, 1, ec_capabilities, Algorithm::EcP256 as u8);
        assert_eq!(
            device.execute_inner(admin, &generate).data,
            93_u16.to_be_bytes()
        );
        let get_wrapped_key = Frame::new(
            CommandCode::GetRsaWrappedKey as u8,
            [
                91_u16.to_be_bytes().as_slice(),
                &[ObjectType::AsymmetricKey as u8],
                93_u16.to_be_bytes().as_slice(),
                &[
                    Algorithm::Aes256 as u8,
                    Algorithm::RsaOaepSha256 as u8,
                    Algorithm::Mgf1Sha384 as u8,
                ],
                label_digest.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        let wrapped_key = device.execute_inner(admin, &get_wrapped_key).data;
        assert!(wrapped_key.len() > 256);
        let delete = Frame::new(
            CommandCode::DeleteObject as u8,
            [
                93_u16.to_be_bytes().as_slice(),
                &[ObjectType::AsymmetricKey as u8],
            ]
            .concat(),
        )
        .unwrap();
        assert!(device.execute_inner(admin, &delete).data.is_empty());

        let mut put_wrapped_key = Vec::new();
        put_wrapped_key.extend_from_slice(&90_u16.to_be_bytes());
        put_wrapped_key.push(ObjectType::AsymmetricKey as u8);
        put_wrapped_key.extend_from_slice(&93_u16.to_be_bytes());
        put_wrapped_key.extend_from_slice(b"PKCS8 wrapped key");
        put_wrapped_key.resize(45, 0);
        put_wrapped_key.extend_from_slice(&1_u16.to_be_bytes());
        put_wrapped_key.extend_from_slice(&ec_capabilities.to_bytes());
        put_wrapped_key.extend_from_slice(&[
            Algorithm::EcP256 as u8,
            Algorithm::RsaOaepSha256 as u8,
            Algorithm::Mgf1Sha384 as u8,
        ]);
        put_wrapped_key.extend_from_slice(&wrapped_key);
        put_wrapped_key.extend_from_slice(&label_digest);
        let put_wrapped_key =
            Frame::new(CommandCode::PutRsaWrappedKey as u8, put_wrapped_key).unwrap();
        assert_eq!(
            device.execute_inner(admin, &put_wrapped_key).data,
            [ObjectType::AsymmetricKey as u8, 0, 93]
        );
        assert_eq!(
            device
                .object(ObjectKey {
                    object_type: ObjectType::AsymmetricKey,
                    id: 93,
                })
                .unwrap()
                .info
                .origin,
            0x12
        );
        let sign = Frame::new(
            CommandCode::SignEcdsa as u8,
            [93_u16.to_be_bytes().as_slice(), &[0x5a; 32]].concat(),
        )
        .unwrap();
        assert_eq!(device.execute_inner(admin, &sign).data.len(), 64);
    }

    #[test]
    fn yubico_otp_aead_matches_the_official_credential_and_otp_layout() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let capabilities = CapabilitySet::from_capabilities([
            Capability::CreateOtpAead,
            Capability::RandomizeOtpAead,
            Capability::DecryptOtp,
            Capability::RewrapFromOtpAeadKey,
            Capability::RewrapToOtpAeadKey,
        ]);
        let master_key: Vec<u8> = (0x80..=0x8f).collect();
        let put = put_otp_aead_key_request(
            70,
            capabilities,
            Algorithm::Aes128YubicoOtp,
            0x1234_5678,
            &master_key,
        );
        assert_eq!(device.execute_inner(admin, &put).data, 70_u16.to_be_bytes());

        let credential_key: Vec<u8> = (0..=15).collect();
        let private_id = [1, 2, 3, 4, 5, 6];
        let create = Frame::new(
            CommandCode::CreateOtpAead as u8,
            [
                70_u16.to_be_bytes().as_slice(),
                credential_key.as_slice(),
                private_id.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        let aead = device.execute_inner(admin, &create).data;
        assert_eq!(aead.len(), 36);

        let otp = [
            0x2f, 0x5d, 0x71, 0xa4, 0x91, 0x5d, 0xec, 0x30, 0x4a, 0xa1, 0x3c, 0xcf, 0x97, 0xbb,
            0x0d, 0xbb,
        ];
        let decrypt = Frame::new(
            CommandCode::DecryptOtp as u8,
            [
                70_u16.to_be_bytes().as_slice(),
                aead.as_slice(),
                otp.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        assert_eq!(
            device.execute_inner(admin, &decrypt).data,
            [1, 0, 1, 1, 1, 0]
        );

        let randomize =
            Frame::new(CommandCode::RandomizeOtpAead as u8, 70_u16.to_be_bytes()).unwrap();
        assert_eq!(device.execute_inner(admin, &randomize).data.len(), 36);
    }

    #[test]
    fn asymmetric_authentication_derives_receipt_and_snapshots_all_authority() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let host_static = p256::SecretKey::from_slice(&[1; 32]).unwrap();
        let host_static_public = host_static.public_key().to_sec1_point(false);
        let capabilities = CapabilitySet::from_capabilities([Capability::GetPseudoRandom]);
        let delegated = CapabilitySet::from_capabilities([Capability::PutOpaque]);
        let mut put = Vec::new();
        put.extend_from_slice(&31_u16.to_be_bytes());
        put.extend_from_slice(b"asymmetric auth");
        put.resize(42, 0);
        put.extend_from_slice(&0b0100_u16.to_be_bytes());
        put.extend_from_slice(&capabilities.to_bytes());
        put.push(AUTHENTICATION_ALGORITHM_EC_P256);
        put.extend_from_slice(&delegated.to_bytes());
        put.extend_from_slice(&host_static_public.as_bytes()[1..]);
        let put = Frame::new(CommandCode::PutAuthenticationKey as u8, put).unwrap();
        assert_eq!(device.execute_inner(admin, &put).data, 31_u16.to_be_bytes());

        let host_ephemeral = p256::SecretKey::from_slice(&[2; 32]).unwrap();
        let host_ephemeral_public = host_ephemeral.public_key().to_sec1_point(false);
        let mut create = 31_u16.to_be_bytes().to_vec();
        create.extend_from_slice(host_ephemeral_public.as_bytes());
        let create = Frame::new(CommandCode::CreateSession as u8, create).unwrap();
        let response = Frame::parse(&device.handle_encoded(&create.encode())).unwrap();
        assert_eq!(response.command, CommandCode::CreateSession as u8 | 0x80);
        assert_eq!(response.data.len(), 1 + 65 + 16);
        let sid = response.data[0];
        let entry = device.sessions.get(&sid).unwrap();
        assert!(entry.authenticated);
        assert_eq!(entry.authorization.capabilities, capabilities);
        assert_eq!(entry.authorization.delegated_capabilities, delegated);
        assert_eq!(entry.authorization.domains, 0b0100);

        let device_ephemeral = p256::PublicKey::from_sec1_bytes(&response.data[1..66]).unwrap();
        let ephemeral_secret = diffie_hellman(
            host_ephemeral.to_nonzero_scalar(),
            device_ephemeral.as_affine(),
        );
        let device_public_frame =
            Frame::new(CommandCode::GetDevicePublicKey as u8, Vec::new()).unwrap();
        let device_public = device.execute_plain(&device_public_frame).data;
        let device_static =
            p256::PublicKey::from_sec1_bytes(&[vec![0x04], device_public[1..].to_vec()].concat())
                .unwrap();
        let static_secret =
            diffie_hellman(host_static.to_nonzero_scalar(), device_static.as_affine());
        let mut session_keys = [0; 64];
        for (index, chunk) in session_keys.chunks_mut(32).enumerate() {
            let mut input = Vec::new();
            input.extend_from_slice(ephemeral_secret.raw_secret_bytes().as_slice());
            input.extend_from_slice(static_secret.raw_secret_bytes().as_slice());
            input.extend_from_slice(&((index + 1) as u32).to_be_bytes());
            input.extend_from_slice(&[0x3c, 0x88, 0x10]);
            chunk.copy_from_slice(&software_key_core::digest::HashAlgorithm::Sha256.digest(&input));
        }
        let mut receipt_input = response.data[1..66].to_vec();
        receipt_input.extend_from_slice(host_ephemeral_public.as_bytes());
        assert_eq!(
            &response.data[66..],
            cmac(&session_keys[..16], &receipt_input).unwrap()
        );
    }

    #[test]
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
    fn hmac_commands_enforce_object_capabilities_and_verify_in_constant_time() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let mut put = Vec::new();
        put.extend_from_slice(&51_u16.to_be_bytes());
        put.extend_from_slice(b"hmac key");
        put.resize(42, 0);
        put.extend_from_slice(&0b1000_u16.to_be_bytes());
        put.extend_from_slice(
            &CapabilitySet::from_capabilities([Capability::SignHmac, Capability::VerifyHmac])
                .to_bytes(),
        );
        put.push(20);
        put.extend_from_slice(&[0x0b; 20]);
        let put = Frame::new(CommandCode::PutHmacKey as u8, put).unwrap();
        assert_eq!(device.execute_inner(admin, &put).data, 51_u16.to_be_bytes());

        let sign = Frame::new(
            CommandCode::SignHmac as u8,
            [51_u16.to_be_bytes().as_slice(), b"Hi There"].concat(),
        )
        .unwrap();
        let signature = device.execute_inner(admin, &sign).data;
        assert_eq!(
            signature,
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
        let verify = Frame::new(
            CommandCode::VerifyHmac as u8,
            [
                51_u16.to_be_bytes().as_slice(),
                signature.as_slice(),
                b"Hi There",
            ]
            .concat(),
        )
        .unwrap();
        assert_eq!(device.execute_inner(admin, &verify).data, [1]);
        let mut tampered = verify;
        *tampered.data.last_mut().unwrap() ^= 1;
        assert_eq!(device.execute_inner(admin, &tampered).data, [0]);
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
        assert!(restored
            .object(ObjectKey {
                object_type: ObjectType::Opaque,
                id: 42,
            })
            .is_some());
        assert_eq!(restored.audit.entries.len(), 1);
        assert_eq!(
            restored.options.command_audit[&(CommandCode::GetPseudoRandom as u8)],
            OPTION_ON
        );
        assert_eq!(restored.device_static_private.as_ref(), &[7; 32]);

        let reset = Frame::new(CommandCode::ResetDevice as u8, vec![0xde]).unwrap();
        assert!(restored.execute_inner(admin, &reset).data.is_empty());
        assert_ne!(restored.device_static_private.as_ref(), &[7; 32]);
        assert!(restored.take_persistent_change().unwrap());
        assert_eq!(restored.state_epoch(), 2);

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
    fn force_audit_enforces_capacity_and_log_index_releases_entries() {
        let mut device = Device::factory_default(DeviceConfig {
            log_capacity: 1,
            ..DeviceConfig::default()
        });
        let admin = device.session_authorization(1).unwrap();
        let audit_random = Frame::new(
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
        assert!(device.execute_inner(admin, &audit_random).data.is_empty());
        let force = Frame::new(
            CommandCode::SetOption as u8,
            vec![OPTION_FORCE_AUDIT, 0, 1, OPTION_ON],
        )
        .unwrap();
        assert!(device.execute_inner(admin, &force).data.is_empty());
        let random = Frame::new(CommandCode::GetPseudoRandom as u8, 1_u16.to_be_bytes()).unwrap();
        assert_eq!(device.execute_inner(admin, &random).data.len(), 1);
        assert_eq!(
            device.execute_inner(admin, &random),
            Frame::error(DeviceError::LogFull)
        );

        let get = Frame::new(CommandCode::GetLogEntries as u8, Vec::new()).unwrap();
        let log = device.execute_inner(admin, &get).data;
        assert_eq!(log[4], 1);
        assert_eq!(log.len(), 5 + 32);
        let number = u16::from_be_bytes(log[5..7].try_into().unwrap());
        let set_index = Frame::new(CommandCode::SetLogIndex as u8, number.to_be_bytes()).unwrap();
        assert!(device.execute_inner(admin, &set_index).data.is_empty());
        assert!(device.audit.entries.is_empty());
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
        assert!(device
            .execute_inner(admin, &enable_authentication_audit)
            .data
            .is_empty());

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

        for command in [
            CommandCode::Echo,
            CommandCode::SessionMessage,
            CommandCode::GetDeviceInfo,
            CommandCode::GetDevicePublicKey,
            CommandCode::CloseSession,
        ] {
            let enable_audit = Frame::new(
                CommandCode::SetOption as u8,
                vec![OPTION_COMMAND_AUDIT, 0, 2, command as u8, OPTION_ON],
            )
            .unwrap();
            assert_eq!(
                device.execute_inner(admin, &enable_audit),
                Frame::error(DeviceError::InvalidData)
            );

            // Keep the execution rule fail-safe if an invalid option map
            // reaches memory through trusted state restoration.
            device
                .options
                .command_audit
                .insert(command as u8, OPTION_ON);
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

    #[test]
    fn attestation_contains_the_generated_target_public_key() {
        let mut device =
            Device::factory_default_with_device_static_private(DeviceConfig::default(), [9; 32])
                .unwrap();
        let admin = device.session_authorization(1).unwrap();
        let generate = generate_asymmetric_key_request(
            88,
            1,
            CapabilitySet::from_capabilities([Capability::SignEcdsa]),
            Algorithm::EcP256 as u8,
        );
        assert_eq!(
            device.execute_inner(admin, &generate).data,
            88_u16.to_be_bytes()
        );
        let attest = Frame::new(
            CommandCode::SignAttestationCertificate as u8,
            [88_u16.to_be_bytes(), 0_u16.to_be_bytes()].concat(),
        )
        .unwrap();
        let response = device.execute_inner(admin, &attest);
        let certificate = x509_cert::Certificate::from_der(&response.data).unwrap();
        let target = device
            .object(ObjectKey {
                object_type: ObjectType::AsymmetricKey,
                id: 88,
            })
            .unwrap();
        assert_eq!(
            certificate.tbs_certificate().subject_public_key_info(),
            &object_subject_public_key_info(target).unwrap()
        );
    }
}
