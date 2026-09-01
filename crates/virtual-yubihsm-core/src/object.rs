use crate::{Algorithm, Capability, CapabilitySet, DeviceError, Result};
use serde::{Deserialize, Serialize};
use software_key_core::{
    software_key_agreement::SoftwareX25519Key,
    software_signing::{EcCurve, KeyKind, SoftwareSigningKey},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const LABEL_LENGTH: usize = 40;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum ObjectType {
    Opaque = 0x01,
    AuthenticationKey = 0x02,
    AsymmetricKey = 0x03,
    WrapKey = 0x04,
    HmacKey = 0x05,
    Template = 0x06,
    OtpAeadKey = 0x07,
    SymmetricKey = 0x08,
    PublicWrapKey = 0x09,
}

impl ObjectType {
    pub fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0x01 => Self::Opaque,
            0x02 => Self::AuthenticationKey,
            0x03 => Self::AsymmetricKey,
            0x04 => Self::WrapKey,
            0x05 => Self::HmacKey,
            0x06 => Self::Template,
            0x07 => Self::OtpAeadKey,
            0x08 => Self::SymmetricKey,
            0x09 => Self::PublicWrapKey,
            _ => return None,
        })
    }

    pub fn deletion_capability(self) -> Capability {
        match self {
            Self::Opaque => Capability::DeleteOpaque,
            Self::AuthenticationKey => Capability::DeleteAuthenticationKey,
            Self::AsymmetricKey => Capability::DeleteAsymmetricKey,
            Self::WrapKey => Capability::DeleteWrapKey,
            Self::HmacKey => Capability::DeleteHmacKey,
            Self::Template => Capability::DeleteTemplate,
            Self::OtpAeadKey => Capability::DeleteOtpAeadKey,
            Self::SymmetricKey => Capability::DeleteSymmetricKey,
            Self::PublicWrapKey => Capability::DeletePublicWrapKey,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ObjectKey {
    pub object_type: ObjectType,
    pub id: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectInfo {
    pub capabilities: CapabilitySet,
    pub id: u16,
    pub length: u16,
    pub domains: u16,
    pub object_type: ObjectType,
    pub algorithm: u8,
    pub sequence: u8,
    pub origin: u8,
    pub label: Vec<u8>,
    pub delegated_capabilities: CapabilitySet,
}

impl ObjectInfo {
    pub fn validate(&self) -> Result<()> {
        if self.id == 0 || self.id == u16::MAX {
            return Err(DeviceError::InvalidId);
        }
        if self.domains == 0 || self.label.len() > LABEL_LENGTH {
            return Err(DeviceError::InvalidData);
        }
        Ok(())
    }

    pub fn key(&self) -> ObjectKey {
        ObjectKey {
            object_type: self.object_type,
            id: self.id,
        }
    }

    pub fn encode(&self) -> [u8; 66] {
        let mut output = [0; 66];
        output[..8].copy_from_slice(&self.capabilities.to_bytes());
        output[8..10].copy_from_slice(&self.id.to_be_bytes());
        output[10..12].copy_from_slice(&self.length.to_be_bytes());
        output[12..14].copy_from_slice(&self.domains.to_be_bytes());
        output[14] = self.object_type as u8;
        output[15] = self.algorithm;
        output[16] = self.sequence;
        output[17] = self.origin;
        output[18..18 + self.label.len()].copy_from_slice(&self.label);
        output[58..].copy_from_slice(&self.delegated_capabilities.to_bytes());
        output
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
pub enum AuthenticationKeyMaterial {
    /// K-ENC followed by K-MAC.
    Symmetric(Vec<u8>),
    /// Uncompressed SEC1 P-256 public point.
    Asymmetric(Vec<u8>),
}

#[derive(Clone, Debug)]
pub enum ObjectMaterial {
    Authentication(AuthenticationKeyMaterial),
    /// Parsed, validated, and precomputed private signing key used at runtime.
    SigningKey(SoftwareSigningKey),
    /// Parsed X25519 private key used at runtime.
    X25519Key(SoftwareX25519Key),
    /// Symmetric, HMAC, and other byte-oriented secret material.
    Secret(Vec<u8>),
    Opaque(Vec<u8>),
    Public(Vec<u8>),
    OtpAeadKey {
        nonce_id: [u8; 4],
        key: Vec<u8>,
    },
}

impl ObjectMaterial {
    pub fn len(&self) -> usize {
        match self {
            Self::Authentication(AuthenticationKeyMaterial::Symmetric(value))
            | Self::Authentication(AuthenticationKeyMaterial::Asymmetric(value))
            | Self::Secret(value)
            | Self::Opaque(value)
            | Self::Public(value) => value.len(),
            Self::SigningKey(key) => match key.key_kind() {
                KeyKind::Ec(curve) => ec_private_length(curve),
                KeyKind::Ed25519 => 32,
                KeyKind::Rsa { modulus_bits } => modulus_bits / 8,
                KeyKind::MlDsa(_) => key.serialized().map_or(0, |value| value.len()),
            },
            Self::X25519Key(_) => 32,
            Self::OtpAeadKey { key, .. } => key.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PartialEq for ObjectMaterial {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Authentication(a), Self::Authentication(b)) => a == b,
            (Self::SigningKey(a), Self::SigningKey(b)) => {
                a.key_kind() == b.key_kind() && a.serialized().ok() == b.serialized().ok()
            }
            (Self::X25519Key(a), Self::X25519Key(b)) => a.serialized() == b.serialized(),
            (Self::Secret(a), Self::Secret(b))
            | (Self::Opaque(a), Self::Opaque(b))
            | (Self::Public(a), Self::Public(b)) => a == b,
            (
                Self::OtpAeadKey {
                    nonce_id: a_nonce,
                    key: a_key,
                },
                Self::OtpAeadKey {
                    nonce_id: b_nonce,
                    key: b_key,
                },
            ) => a_nonce == b_nonce && a_key == b_key,
            _ => false,
        }
    }
}

impl Eq for ObjectMaterial {}

impl Zeroize for ObjectMaterial {
    fn zeroize(&mut self) {
        match self {
            Self::Authentication(value) => value.zeroize(),
            // Typed private keys clear themselves when their owning wrapper is
            // dropped; they are intentionally never converted back to bytes
            // merely to wipe a temporary representation.
            Self::SigningKey(_) | Self::X25519Key(_) => {}
            Self::Secret(value) | Self::Opaque(value) | Self::Public(value) => value.zeroize(),
            Self::OtpAeadKey { nonce_id, key } => {
                nonce_id.zeroize();
                key.zeroize();
            }
        }
    }
}

impl Drop for ObjectMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ObjectMaterial {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRecord {
    pub info: ObjectInfo,
    pub material: ObjectMaterial,
}

/// Persistence-only representation. It intentionally contains no parsed
/// runtime keys and retains the existing CBOR shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct StoredObjectRecord {
    pub(crate) info: ObjectInfo,
    pub(crate) material: StoredObjectMaterial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
pub(crate) enum StoredObjectMaterial {
    Authentication(AuthenticationKeyMaterial),
    Secret(Vec<u8>),
    Opaque(Vec<u8>),
    Public(Vec<u8>),
    OtpAeadKey { nonce_id: [u8; 4], key: Vec<u8> },
}

impl StoredObjectMaterial {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Authentication(AuthenticationKeyMaterial::Symmetric(value))
            | Self::Authentication(AuthenticationKeyMaterial::Asymmetric(value))
            | Self::Secret(value)
            | Self::Opaque(value)
            | Self::Public(value) => value.len(),
            Self::OtpAeadKey { key, .. } => key.len(),
        }
    }
}

impl ObjectRecord {
    pub(crate) fn to_stored(&self) -> Result<StoredObjectRecord> {
        let material = match &self.material {
            ObjectMaterial::Authentication(value) => {
                StoredObjectMaterial::Authentication(value.clone())
            }
            ObjectMaterial::SigningKey(key) => {
                let algorithm =
                    Algorithm::from_byte(self.info.algorithm).ok_or(DeviceError::InvalidData)?;
                let encoded = if algorithm.is_rsa_key() {
                    let [p, q, _, _, _] = key
                        .rsa_crt_components()
                        .map_err(|_| DeviceError::InvalidData)?;
                    let component_length = algorithm
                        .asymmetric_key_length()
                        .ok_or(DeviceError::InvalidData)?
                        / 2;
                    let mut encoded = left_pad(&p, component_length)?;
                    encoded.extend_from_slice(&left_pad(&q, component_length)?);
                    encoded
                } else {
                    key.serialized()
                        .map_err(|_| DeviceError::InvalidData)?
                        .to_vec()
                };
                StoredObjectMaterial::Secret(encoded)
            }
            ObjectMaterial::X25519Key(key) => {
                StoredObjectMaterial::Secret(key.serialized().to_vec())
            }
            ObjectMaterial::Secret(value) => StoredObjectMaterial::Secret(value.clone()),
            ObjectMaterial::Opaque(value) => StoredObjectMaterial::Opaque(value.clone()),
            ObjectMaterial::Public(value) => StoredObjectMaterial::Public(value.clone()),
            ObjectMaterial::OtpAeadKey { nonce_id, key } => StoredObjectMaterial::OtpAeadKey {
                nonce_id: *nonce_id,
                key: key.clone(),
            },
        };
        Ok(StoredObjectRecord {
            info: self.info.clone(),
            material,
        })
    }

    pub(crate) fn from_stored(stored: StoredObjectRecord) -> Result<Self> {
        let material = match &stored.material {
            StoredObjectMaterial::Authentication(value) => {
                ObjectMaterial::Authentication(value.clone())
            }
            StoredObjectMaterial::Secret(value)
                if stored.info.object_type == ObjectType::AsymmetricKey
                    || stored.info.object_type == ObjectType::WrapKey
                        && Algorithm::from_byte(stored.info.algorithm)
                            .is_some_and(Algorithm::is_rsa_key) =>
            {
                typed_private_material(&stored.info, value)?
            }
            StoredObjectMaterial::Secret(value) => ObjectMaterial::Secret(value.clone()),
            StoredObjectMaterial::Opaque(value) => ObjectMaterial::Opaque(value.clone()),
            StoredObjectMaterial::Public(value) => ObjectMaterial::Public(value.clone()),
            StoredObjectMaterial::OtpAeadKey { nonce_id, key } => ObjectMaterial::OtpAeadKey {
                nonce_id: *nonce_id,
                key: key.clone(),
            },
        };
        Ok(Self {
            info: stored.info,
            material,
        })
    }

    /// Convert boundary byte material to the authoritative parsed runtime form.
    pub(crate) fn promote_private_material(&mut self) -> Result<()> {
        let ObjectMaterial::Secret(value) = &self.material else {
            return Ok(());
        };
        if self.info.object_type == ObjectType::AsymmetricKey
            || self.info.object_type == ObjectType::WrapKey
                && Algorithm::from_byte(self.info.algorithm).is_some_and(Algorithm::is_rsa_key)
        {
            self.material = typed_private_material(&self.info, value)?;
        }
        Ok(())
    }

    pub fn expected_info_length(&self) -> Result<usize> {
        match self.info.object_type {
            ObjectType::AuthenticationKey => Ok(self.material.len() + 8),
            ObjectType::AsymmetricKey => Algorithm::from_byte(self.info.algorithm)
                .and_then(Algorithm::asymmetric_object_length)
                .ok_or(DeviceError::InvalidData),
            ObjectType::WrapKey => match Algorithm::from_byte(self.info.algorithm) {
                Some(algorithm) if algorithm.is_rsa_key() => algorithm
                    .asymmetric_object_length()
                    .and_then(|length| length.checked_add(8))
                    .ok_or(DeviceError::InvalidData),
                Some(
                    Algorithm::Aes128CcmWrap | Algorithm::Aes192CcmWrap | Algorithm::Aes256CcmWrap,
                ) => Ok(self.material.len() + 8),
                _ => Err(DeviceError::InvalidData),
            },
            ObjectType::HmacKey => Algorithm::from_byte(self.info.algorithm)
                .and_then(Algorithm::hmac_object_length)
                .ok_or(DeviceError::InvalidData),
            ObjectType::OtpAeadKey => Ok(self.material.len() + 4),
            ObjectType::PublicWrapKey => Ok(self.material.len() + 8),
            _ => Ok(self.material.len()),
        }
    }

    pub fn normalize_info_length(&mut self) -> Result<()> {
        self.info.length = self
            .expected_info_length()?
            .try_into()
            .map_err(|_| DeviceError::WrongLength)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.info.validate()?;
        let algorithm = Algorithm::from_byte(self.info.algorithm);
        let stores_private_asymmetric_key = matches!(
            self.info.object_type,
            ObjectType::AsymmetricKey | ObjectType::WrapKey
        ) && algorithm.is_some_and(|algorithm| {
            matches!(self.info.object_type, ObjectType::AsymmetricKey) || algorithm.is_rsa_key()
        });
        if stores_private_asymmetric_key
            && algorithm.and_then(Algorithm::asymmetric_key_length) != Some(self.material.len())
        {
            return Err(DeviceError::InvalidData);
        }
        if usize::from(self.info.length) != self.expected_info_length()? {
            return Err(DeviceError::InvalidData);
        }
        Ok(())
    }
}

fn typed_private_material(info: &ObjectInfo, encoded: &[u8]) -> Result<ObjectMaterial> {
    let algorithm = Algorithm::from_byte(info.algorithm).ok_or(DeviceError::InvalidData)?;
    if algorithm == Algorithm::X25519 {
        return SoftwareX25519Key::from_serialized(encoded)
            .map(ObjectMaterial::X25519Key)
            .map_err(|_| DeviceError::InvalidData);
    }
    let key = if algorithm.is_rsa_key() {
        let expected = algorithm
            .asymmetric_key_length()
            .ok_or(DeviceError::InvalidData)?;
        if encoded.len() != expected || expected % 2 != 0 {
            return Err(DeviceError::InvalidData);
        }
        let (p, q) = encoded.split_at(expected / 2);
        SoftwareSigningKey::from_rsa_primes(p, q, &[1, 0, 1])
    } else {
        SoftwareSigningKey::from_serialized_for_kind(key_kind(algorithm)?, encoded)
    }
    .map_err(|_| DeviceError::InvalidData)?;
    Ok(ObjectMaterial::SigningKey(key))
}

fn key_kind(algorithm: Algorithm) -> Result<KeyKind> {
    Ok(match algorithm {
        Algorithm::EcP224 => KeyKind::Ec(EcCurve::P224),
        Algorithm::EcP256 => KeyKind::Ec(EcCurve::P256),
        Algorithm::EcP384 => KeyKind::Ec(EcCurve::P384),
        Algorithm::EcP521 => KeyKind::Ec(EcCurve::P521),
        Algorithm::EcK256 => KeyKind::Ec(EcCurve::Secp256k1),
        Algorithm::EcBrainpoolP256 => KeyKind::Ec(EcCurve::BrainpoolP256),
        Algorithm::EcBrainpoolP384 => KeyKind::Ec(EcCurve::BrainpoolP384),
        Algorithm::EcBrainpoolP512 => KeyKind::Ec(EcCurve::BrainpoolP512),
        Algorithm::Ed25519 => KeyKind::Ed25519,
        Algorithm::Rsa2048 => KeyKind::Rsa { modulus_bits: 2048 },
        Algorithm::Rsa3072 => KeyKind::Rsa { modulus_bits: 3072 },
        Algorithm::Rsa4096 => KeyKind::Rsa { modulus_bits: 4096 },
        _ => return Err(DeviceError::InvalidData),
    })
}

const fn ec_private_length(curve: EcCurve) -> usize {
    match curve {
        EcCurve::P224 => 28,
        EcCurve::P256 | EcCurve::Secp256k1 | EcCurve::BrainpoolP256 => 32,
        EcCurve::P384 | EcCurve::BrainpoolP384 => 48,
        EcCurve::P521 => 66,
        EcCurve::BrainpoolP512 => 64,
    }
}

fn left_pad(value: &[u8], length: usize) -> Result<Vec<u8>> {
    if value.len() > length {
        return Err(DeviceError::InvalidData);
    }
    let mut padded = vec![0; length];
    padded[length - value.len()..].copy_from_slice(value);
    Ok(padded)
}
