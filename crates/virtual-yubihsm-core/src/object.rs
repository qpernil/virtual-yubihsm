use crate::{Algorithm, Capability, CapabilitySet, DeviceError, Result};
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
pub enum ObjectMaterial {
    Authentication(AuthenticationKeyMaterial),
    Secret(Vec<u8>),
    Opaque(Vec<u8>),
    Public(Vec<u8>),
    OtpAeadKey { nonce_id: [u8; 4], key: Vec<u8> },
}

impl ObjectMaterial {
    pub fn len(&self) -> usize {
        match self {
            Self::Authentication(AuthenticationKeyMaterial::Symmetric(value))
            | Self::Authentication(AuthenticationKeyMaterial::Asymmetric(value))
            | Self::Secret(value)
            | Self::Opaque(value)
            | Self::Public(value) => value.len(),
            Self::OtpAeadKey { key, .. } => key.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectRecord {
    pub info: ObjectInfo,
    pub material: ObjectMaterial,
}

impl ObjectRecord {
    pub fn expected_info_length(&self) -> Result<usize> {
        match self.info.object_type {
            ObjectType::AsymmetricKey => Algorithm::from_byte(self.info.algorithm)
                .and_then(Algorithm::asymmetric_object_length)
                .ok_or(DeviceError::InvalidData),
            ObjectType::WrapKey
                if Algorithm::from_byte(self.info.algorithm).is_some_and(Algorithm::is_rsa_key) =>
            {
                Algorithm::from_byte(self.info.algorithm)
                    .and_then(Algorithm::asymmetric_object_length)
                    .ok_or(DeviceError::InvalidData)
            }
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
