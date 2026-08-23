use crate::{
    session::{
        random_secret_key, SecureSession, SessionEntry, AUTHENTICATION_ALGORITHM_AES128_YUBICO,
        AUTHENTICATION_ALGORITHM_EC_P256, CHALLENGE_LENGTH, P256_PUBLIC_KEY_LENGTH,
    },
    AuthenticationKeyMaterial, Capability, CapabilitySet, CommandCode, DeviceError, Frame,
    ObjectInfo, ObjectKey, ObjectMaterial, ObjectRecord, ObjectType, Result, SessionAuthorization,
};
use hmac::{Hmac, Mac};
use p256::{elliptic_curve::sec1::ToSec1Point, SecretKey};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use software_key_core::{
    software_key_agreement::derive_with_signing_key,
    software_signing::{SoftwarePublicKey, SoftwareSigningAlgorithm, SoftwareSigningKey},
};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAX_OBJECTS: usize = 256;
const MAX_SESSIONS: u8 = 16;
const DEFAULT_AUTHENTICATION_ALGORITHM: u8 = AUTHENTICATION_ALGORITHM_AES128_YUBICO;
const OPAQUE_DATA_ALGORITHM: u8 = 30;

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub version: [u8; 3],
    pub serial: u32,
    pub log_capacity: u8,
    pub algorithms: Vec<u8>,
    pub part_number: [u8; 13],
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            version: [2, 4, 1],
            serial: 12_345_678,
            log_capacity: 62,
            algorithms: vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                28, 29, 30, 31, 32, 33, 34, 35, 36, 38, 41, 42, 43, 46, 49, 50, 51, 52, 53, 54, 55,
                56,
            ],
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
    next_sequence: u8,
}

impl Device {
    pub fn factory_default(config: DeviceConfig) -> Self {
        let static_key = random_secret_key().expect("operating-system random source unavailable");
        let mut device = Self {
            config,
            objects: BTreeMap::new(),
            sessions: BTreeMap::new(),
            device_static_private: Zeroizing::new(static_key.to_bytes().into()),
            next_sequence: 1,
        };
        device.install_factory_authentication_key();
        device
    }

    /// Process one complete YubiHSM connector message.
    pub fn handle_encoded(&mut self, encoded: &[u8]) -> Vec<u8> {
        let response = match Frame::parse(encoded) {
            Ok(request) => self.handle_frame(request),
            Err(error) => Frame::error(error),
        };
        response.encode()
    }

    /// Process one complete outer protocol frame.
    pub fn handle_frame(&mut self, request: Frame) -> Frame {
        let result = match CommandCode::from_byte(request.command) {
            Some(
                CommandCode::Echo | CommandCode::GetDeviceInfo | CommandCode::GetDevicePublicKey,
            ) => {
                return self.execute_plain(&request);
            }
            Some(CommandCode::CreateSession) => self.create_session(&request.data),
            Some(CommandCode::AuthenticateSession) => self.authenticate_session(&request),
            Some(CommandCode::SessionMessage) => self.session_message(&request),
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
        let result = match CommandCode::from_byte(request.command) {
            Some(CommandCode::Echo) => Ok(request.data.clone()),
            Some(CommandCode::GetDeviceInfo) => self.get_device_info(&request.data),
            Some(CommandCode::GetDevicePublicKey) => self.get_device_public_key(&request.data),
            Some(_) => Err(DeviceError::InvalidSession),
            None => Err(DeviceError::InvalidCommand),
        };
        match result {
            Ok(data) => Frame::response(request.command, data),
            Err(error) => Frame::error(error),
        }
    }

    fn create_session(&mut self, data: &[u8]) -> Result<Frame> {
        if data.len() < 2 {
            return Err(DeviceError::WrongLength);
        }
        let authentication_key_id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let authorization = self.session_authorization(authentication_key_id)?;
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
                    SecureSession::begin_symmetric(sid, static_keys, &data[2..], card_challenge)?;
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
                let (secure, device_ephemeral_public, receipt) = SecureSession::begin_asymmetric(
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
                Ok(Frame::response(CommandCode::CreateSession as u8, response))
            }
        }
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
        Ok(Frame::response(
            CommandCode::AuthenticateSession as u8,
            Vec::new(),
        ))
    }

    fn session_message(&mut self, request: &Frame) -> Result<Frame> {
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
        let closes_session = matches!(
            CommandCode::from_byte(inner.command),
            Some(CommandCode::CloseSession | CommandCode::ResetDevice)
        );
        let response = self.execute_inner(entry.authorization, &inner);
        let outer = entry.secure.encrypt_response(&response)?;
        if !closes_session {
            self.sessions.insert(sid, entry);
        }
        Ok(outer)
    }

    fn get_device_public_key(&self, data: &[u8]) -> Result<Vec<u8>> {
        require_empty(data)?;
        let private = SecretKey::from_slice(self.device_static_private.as_ref())
            .map_err(|_| DeviceError::StorageFailed)?;
        let point = private.public_key().to_sec1_point(false);
        let mut public = point.as_bytes().to_vec();
        public[0] = AUTHENTICATION_ALGORITHM_EC_P256;
        Ok(public)
    }

    /// Execute an already decrypted session command under a snapshotted
    /// Authentication Key authorization context.
    pub fn execute_inner(&mut self, authorization: SessionAuthorization, request: &Frame) -> Frame {
        let result = self.execute_inner_result(authorization, request);
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

    fn execute_inner_result(
        &mut self,
        authorization: SessionAuthorization,
        request: &Frame,
    ) -> Result<Vec<u8>> {
        let command = CommandCode::from_byte(request.command).ok_or(DeviceError::InvalidCommand)?;
        if let Some(required) = command.required_session_capability() {
            authorization.require_capability(required)?;
        }
        match command {
            CommandCode::CloseSession => require_empty(&request.data).map(|()| Vec::new()),
            CommandCode::GetStorageInfo => {
                require_empty(&request.data)?;
                let used = self.objects.len() as u16;
                let free = (MAX_OBJECTS - self.objects.len()) as u16;
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
            CommandCode::PutAuthenticationKey => {
                self.put_authentication_key(authorization, &request.data)
            }
            CommandCode::ChangeAuthenticationKey => {
                self.change_authentication_key(authorization, &request.data)
            }
            CommandCode::PutOpaque => self.put_opaque(authorization, &request.data),
            CommandCode::PutAsymmetricKey => {
                self.put_asymmetric_key(authorization, &request.data, false)
            }
            CommandCode::GenerateAsymmetricKey => {
                self.put_asymmetric_key(authorization, &request.data, true)
            }
            CommandCode::GetPublicKey => self.get_public_key(authorization, &request.data),
            CommandCode::SignEcdsa => self.sign_ecdsa(authorization, &request.data),
            CommandCode::SignEddsa => self.sign_eddsa(authorization, &request.data),
            CommandCode::DeriveEcdh => self.derive_ecdh(authorization, &request.data),
            CommandCode::PutHmacKey => self.put_hmac_key(authorization, &request.data, false),
            CommandCode::GenerateHmacKey => self.put_hmac_key(authorization, &request.data, true),
            CommandCode::SignHmac => self.sign_hmac(authorization, &request.data),
            CommandCode::VerifyHmac => self.verify_hmac(authorization, &request.data),
            CommandCode::GetOpaque => {
                let id = parse_u16(&request.data)?;
                let object = self
                    .objects
                    .get(&ObjectKey {
                        object_type: ObjectType::Opaque,
                        id,
                    })
                    .ok_or(DeviceError::ObjectNotFound)?;
                authorization.authorize_use(
                    &object.info,
                    Capability::GetOpaque,
                    Capability::GetOpaque,
                )?;
                match &object.material {
                    ObjectMaterial::Opaque(data) => Ok(data.clone()),
                    _ => Err(DeviceError::InvalidData),
                }
            }
            CommandCode::DeleteObject => {
                let key = parse_object_key(&request.data)?;
                let object = self.objects.get(&key).ok_or(DeviceError::ObjectNotFound)?;
                authorization.authorize_delete(&object.info)?;
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
                self.objects.clear();
                self.next_sequence = 1;
                self.sessions.clear();
                self.install_factory_authentication_key();
                Ok(Vec::new())
            }
            _ => Err(DeviceError::InvalidCommand),
        }
    }

    fn get_device_info(&self, data: &[u8]) -> Result<Vec<u8>> {
        match data {
            [] => {
                let mut output = Vec::with_capacity(9 + self.config.algorithms.len());
                output.extend_from_slice(&self.config.version);
                output.extend_from_slice(&self.config.serial.to_be_bytes());
                output.push(self.config.log_capacity);
                output.push(0);
                output.extend_from_slice(&self.config.algorithms);
                Ok(output)
            }
            [1] => Ok(self.config.part_number.to_vec()),
            _ => Err(DeviceError::InvalidData),
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
        let id = self.resolve_id(
            ObjectType::Opaque,
            u16::from_be_bytes(data[..2].try_into().unwrap()),
        )?;
        let material = data[53..].to_vec();
        let info = ObjectInfo {
            capabilities: CapabilitySet::from_bytes(data[44..52].try_into().unwrap()),
            id,
            length: u16::try_from(material.len()).map_err(|_| DeviceError::WrongLength)?,
            domains: u16::from_be_bytes(data[42..44].try_into().unwrap()),
            object_type: ObjectType::Opaque,
            algorithm: data[52],
            sequence: self.allocate_sequence(),
            origin: 2,
            label: trim_label(&data[2..42]),
            delegated_capabilities: CapabilitySet::NONE,
        };
        if info.algorithm != OPAQUE_DATA_ALGORITHM && material.is_empty() {
            return Err(DeviceError::InvalidData);
        }
        authorization.authorize_create(&info, Capability::PutOpaque)?;
        let record = ObjectRecord {
            info,
            material: ObjectMaterial::Opaque(material),
        };
        record.validate()?;
        self.objects.insert(record.info.key(), record);
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
            sequence: self.allocate_sequence(),
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
        self.objects.insert(record.info.key(), record);
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
        let algorithm = data[52];
        let (software_algorithm, expected_length) = asymmetric_key_algorithm(algorithm)?;
        let secret = if generate {
            SoftwareSigningKey::generate(software_algorithm)
                .and_then(|key| key.serialized())
                .map_err(|_| DeviceError::StorageFailed)?
                .to_vec()
        } else {
            if data.len() != HEADER_LENGTH + expected_length {
                return Err(DeviceError::WrongLength);
            }
            let secret = data[HEADER_LENGTH..].to_vec();
            SoftwareSigningKey::from_serialized(software_algorithm, &secret)
                .map_err(|_| DeviceError::InvalidData)?;
            secret
        };
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
            algorithm,
            sequence: self.allocate_sequence(),
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
        self.objects.insert(record.info.key(), record);
        Ok(id.to_be_bytes().to_vec())
    }

    fn get_public_key(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u16(data)?;
        let object = self.asymmetric_object(authorization, id)?;
        let key = signing_key(object)?;
        let mut output = vec![object.info.algorithm];
        match key.public_key() {
            SoftwarePublicKey::Ec { uncompressed, .. } => {
                output.extend_from_slice(&uncompressed[1..]);
            }
            SoftwarePublicKey::Ed25519(public) => output.extend_from_slice(&public),
            SoftwarePublicKey::Rsa { modulus, .. } => output.extend_from_slice(&modulus),
            SoftwarePublicKey::MlDsa { public_key, .. } => output.extend_from_slice(&public_key),
        }
        Ok(output)
    }

    fn sign_ecdsa(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 3 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.asymmetric_object(authorization, id)?;
        authorization.authorize_use(&object.info, Capability::SignEcdsa, Capability::SignEcdsa)?;
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
        authorization.authorize_use(&object.info, Capability::SignEddsa, Capability::SignEddsa)?;
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
        authorization.authorize_use(
            &object.info,
            Capability::DeriveEcdh,
            Capability::DeriveEcdh,
        )?;
        derive_with_signing_key(&signing_key(object)?, &data[2..])
            .map(|secret| secret.to_vec())
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
            sequence: self.allocate_sequence(),
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
        self.objects.insert(record.info.key(), record);
        Ok(id.to_be_bytes().to_vec())
    }

    fn sign_hmac(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 2 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.hmac_object(authorization, id)?;
        authorization.authorize_use(&object.info, Capability::SignHmac, Capability::SignHmac)?;
        calculate_hmac(object, &data[2..])
    }

    fn verify_hmac(&self, authorization: SessionAuthorization, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 2 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let object = self.hmac_object(authorization, id)?;
        authorization.authorize_use(
            &object.info,
            Capability::VerifyHmac,
            Capability::VerifyHmac,
        )?;
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
        Ok(object)
    }

    fn change_authentication_key(
        &mut self,
        authorization: SessionAuthorization,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if data.len() < 3 {
            return Err(DeviceError::WrongLength);
        }
        let id = u16::from_be_bytes(data[..2].try_into().unwrap());
        let algorithm = data[2];
        let key_length = authentication_key_length(algorithm)?;
        if data.len() != 3 + key_length {
            return Err(DeviceError::WrongLength);
        }
        let key = ObjectKey {
            object_type: ObjectType::AuthenticationKey,
            id,
        };
        let info = self
            .objects
            .get(&key)
            .ok_or(DeviceError::ObjectNotFound)?
            .info
            .clone();
        authorization.authorize_use(
            &info,
            Capability::ChangeAuthenticationKey,
            Capability::ChangeAuthenticationKey,
        )?;
        let material = parse_authentication_key_material(algorithm, &data[3..])?;
        let record = self.objects.get_mut(&key).unwrap();
        record.info.algorithm = algorithm;
        record.info.length = key_length as u16;
        record.material = ObjectMaterial::Authentication(material);
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
        (1..u16::MAX)
            .find(|id| {
                !self.objects.contains_key(&ObjectKey {
                    object_type,
                    id: *id,
                })
            })
            .ok_or(DeviceError::StorageFailed)
    }

    fn allocate_sequence(&mut self) -> u8 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1).max(1);
        sequence
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
        self.objects.insert(record.info.key(), record);
    }
}

fn yubico_password_kdf(password: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut output = Zeroizing::new([0; 32]);
    pbkdf2_hmac::<Sha256>(password, b"Yubico", 10_000, output.as_mut());
    output
}

fn authentication_key_length(algorithm: u8) -> Result<usize> {
    match algorithm {
        AUTHENTICATION_ALGORITHM_AES128_YUBICO => Ok(32),
        AUTHENTICATION_ALGORITHM_EC_P256 => Ok(64),
        _ => Err(DeviceError::InvalidData),
    }
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
            p256::PublicKey::from_sec1_bytes(&encoded).map_err(|_| DeviceError::InvalidData)?;
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
        12 => Ok((SoftwareSigningAlgorithm::EcdsaP256Sha256, 32)),
        13 => Ok((SoftwareSigningAlgorithm::EcdsaP384Sha384, 48)),
        14 => Ok((SoftwareSigningAlgorithm::EcdsaP521Sha512, 66)),
        15 => Ok((SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256, 32)),
        46 => Ok((SoftwareSigningAlgorithm::Ed25519, 32)),
        _ => Err(DeviceError::InvalidData),
    }
}

fn signing_key(object: &ObjectRecord) -> Result<SoftwareSigningKey> {
    let ObjectMaterial::Secret(secret) = &object.material else {
        return Err(DeviceError::InvalidData);
    };
    let (algorithm, _) = asymmetric_key_algorithm(object.info.algorithm)?;
    SoftwareSigningKey::from_serialized(algorithm, secret).map_err(|_| DeviceError::InvalidData)
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
    macro_rules! calculate {
        ($digest:ty) => {{
            let mut mac = <Hmac<$digest> as hmac::digest::KeyInit>::new_from_slice(secret)
                .map_err(|_| DeviceError::InvalidData)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }
    match object.info.algorithm {
        19 => calculate!(Sha1),
        20 => calculate!(Sha256),
        21 => calculate!(Sha384),
        22 => calculate!(Sha512),
        _ => Err(DeviceError::InvalidData),
    }
}

fn parse_u16(data: &[u8]) -> Result<u16> {
    data.try_into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_channel_crypto::{
        cbc_decrypt, cbc_encrypt, cmac, encrypt_block, pad, scp03_kdf, unpad, BLOCK_SIZE,
    };
    use p256::ecdh::diffie_hellman;
    use sha2::Digest;
    use software_key_core::software_signing::EcCurve;

    fn put_opaque_request(id: u16, domains: u16, capabilities: CapabilitySet) -> Frame {
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(b"state");
        data.resize(42, 0);
        data.extend_from_slice(&domains.to_be_bytes());
        data.extend_from_slice(&capabilities.to_bytes());
        data.push(OPAQUE_DATA_ALGORITHM);
        data.extend_from_slice(b"payload");
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
    fn opaque_lifecycle_enforces_session_authorization() {
        let mut device = Device::factory_default(DeviceConfig::default());
        let admin = device.session_authorization(1).unwrap();
        let object_caps = CapabilitySet::from_capabilities([Capability::GetOpaque]);
        let response = device.execute_inner(admin, &put_opaque_request(12, 2, object_caps));
        assert_eq!(response.data, 12_u16.to_be_bytes());

        let get = Frame::new(CommandCode::GetOpaque as u8, 12_u16.to_be_bytes()).unwrap();
        assert_eq!(device.execute_inner(admin, &get).data, b"payload");

        let info = Frame::new(
            CommandCode::GetObjectInfo as u8,
            [12_u16.to_be_bytes().as_slice(), &[ObjectType::Opaque as u8]].concat(),
        )
        .unwrap();
        assert_eq!(device.execute_inner(admin, &info).data.len(), 66);
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
            device.execute_inner(admin, &change).data,
            23_u16.to_be_bytes()
        );
        assert_eq!(
            device.authentication_key_material(23).unwrap(),
            &AuthenticationKeyMaterial::Symmetric(vec![0x77; 32])
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
        let inner = Frame::new(CommandCode::GetStorageInfo as u8, Vec::new()).unwrap();
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
        assert_eq!(
            inner_response.command,
            CommandCode::GetStorageInfo as u8 | 0x80
        );
        assert_eq!(inner_response.data.len(), 10);
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

        let digest = Sha256::digest(b"protocol-neutral key implementation");
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
            chunk.copy_from_slice(&Sha256::digest(&input));
        }
        let mut receipt_input = response.data[1..66].to_vec();
        receipt_input.extend_from_slice(host_ephemeral_public.as_bytes());
        assert_eq!(
            &response.data[66..],
            cmac(&session_keys[..16], &receipt_input).unwrap()
        );
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
}
