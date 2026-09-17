use crate::{
    CapabilitySet, DeviceError, ObjectInfo, ObjectKey, ObjectType, Result, SessionObjectCommand,
    session_object::SessionObjectKind,
    wire::{Decode, Reader},
};
use software_key_core::counter_kdf::{CounterKdfField, IntegerFormat, LengthMethod};

macro_rules! empty_requests {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name;
        impl Decode<'_> for $name {
            fn decode(_reader: &mut Reader<'_>) -> Result<Self> { Ok(Self) }
        }
    )+};
}

macro_rules! remainder_requests {
    ($($name:ident => $field:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name<'a> { pub(crate) $field: &'a [u8] }
        impl<'a> Decode<'a> for $name<'a> {
            fn decode(reader: &mut Reader<'a>) -> Result<Self> {
                Ok(Self { $field: reader.read_remainder() })
            }
        }
    )+};
}

macro_rules! u8_requests {
    ($($name:ident => $field:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name { pub(crate) $field: u8 }
        impl Decode<'_> for $name {
            fn decode(reader: &mut Reader<'_>) -> Result<Self> {
                Ok(Self { $field: reader.read_u8()? })
            }
        }
    )+};
}

macro_rules! u16_requests {
    ($($name:ident => $field:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name { pub(crate) $field: u16 }
        impl Decode<'_> for $name {
            fn decode(reader: &mut Reader<'_>) -> Result<Self> {
                Ok(Self { $field: reader.read_u16()? })
            }
        }
    )+};
}

macro_rules! id_remainder_requests {
    ($($name:ident => $field:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name<'a> {
            pub(crate) id: u16,
            pub(crate) $field: &'a [u8],
        }
        impl<'a> Decode<'a> for $name<'a> {
            fn decode(reader: &mut Reader<'a>) -> Result<Self> {
                Ok(Self { id: reader.read_u16()?, $field: reader.read_remainder() })
            }
        }
    )+};
}

empty_requests!(
    GetDevicePublicKeyRequest,
    CloseSessionRequest,
    GetStorageInfoRequest,
    GetLogEntriesRequest,
    ResetDeviceRequest,
);

remainder_requests!(
    EchoRequest => data,
);

u8_requests!(
    GetOptionRequest => option,
    BlinkDeviceRequest => duration,
);

u16_requests!(
    GetPseudoRandomRequest => length,
    SetLogIndexRequest => index,
    GetOpaqueRequest => id,
    GetTemplateRequest => id,
    RandomizeOtpAeadRequest => id,
);

id_remainder_requests!(
    SignPkcs1Request => payload,
    SignEcdsaRequest => digest,
    SignEddsaRequest => message,
    DecapsulateMlKemRequest => ciphertext,
    DeriveEcdhRequest => peer_public,
    DecryptPkcs1Request => ciphertext,
    SignHmacRequest => message,
    VerifyHmacRequest => signature_and_message,
    WrapDataRequest => plaintext,
    UnwrapDataRequest => wrapped,
    EncryptEcbRequest => plaintext,
    DecryptEcbRequest => ciphertext,
);

#[derive(Default)]
pub(crate) struct ObjectFilters {
    id: Option<u16>,
    object_type: Option<ObjectType>,
    domains: Option<u16>,
    capabilities: Option<CapabilitySet>,
    algorithm: Option<u8>,
    label: Option<Vec<u8>>,
}

impl Decode<'_> for ObjectFilters {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let mut filters = Self::default();
        while reader.remaining_len() != 0 {
            match reader.read_u8()? {
                1 => filters.id = Some(reader.read_u16()?),
                2 => {
                    filters.object_type = Some(
                        ObjectType::from_byte(reader.read_u8()?).ok_or(DeviceError::InvalidData)?,
                    );
                }
                3 => filters.domains = Some(reader.read_u16()?),
                4 => {
                    filters.capabilities = Some(CapabilitySet::from_bytes(*reader.read_array()?));
                }
                5 => filters.algorithm = Some(reader.read_u8()?),
                6 => filters.label = Some(trim_label(reader.read_array::<40>()?)),
                _ => return Err(DeviceError::InvalidData),
            }
        }
        Ok(filters)
    }
}

impl ObjectFilters {
    pub(crate) fn matches(&self, object: &ObjectInfo) -> bool {
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

fn trim_label(label: &[u8]) -> Vec<u8> {
    label
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default()
        .to_vec()
}

pub(crate) struct ListObjectsRequest {
    pub(crate) filters: ObjectFilters,
}

impl Decode<'_> for ListObjectsRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            filters: ObjectFilters::decode(reader)?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct GetDeviceInfoRequest {
    pub(crate) selector: Option<u8>,
}

impl Decode<'_> for GetDeviceInfoRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            selector: match reader.remaining_len() {
                0 => None,
                1 => Some(reader.read_u8()?),
                _ => return Err(DeviceError::InvalidData),
            },
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateSessionRequest<'a> {
    pub(crate) authentication_key_id: u16,
    pub(crate) host_challenge_or_public_key: &'a [u8],
}

impl<'a> Decode<'a> for CreateSessionRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            authentication_key_id: reader.read_u16()?,
            host_challenge_or_public_key: reader.read_remainder(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionEnvelopeRequest<'a> {
    pub(crate) session_id: u8,
    pub(crate) _body: &'a [u8],
}

impl<'a> Decode<'a> for SessionEnvelopeRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            session_id: reader.read_u8()?,
            _body: reader.read_remainder(),
        })
    }
}

macro_rules! session_envelope_requests {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name<'a>(pub(crate) SessionEnvelopeRequest<'a>);
        impl<'a> Decode<'a> for $name<'a> {
            fn decode(reader: &mut Reader<'a>) -> Result<Self> {
                Ok(Self(SessionEnvelopeRequest::decode(reader)?))
            }
        }
    )+};
}

session_envelope_requests!(AuthenticateSessionRequest, SessionMessageRequest);

#[derive(Clone, Copy, Debug)]
pub(crate) struct ObjectKeyRequest {
    pub(crate) key: ObjectKey,
}

impl Decode<'_> for ObjectKeyRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let id = reader.read_u16()?;
        let object_type =
            ObjectType::from_byte(reader.read_u8()?).ok_or(DeviceError::InvalidData)?;
        Ok(Self {
            key: ObjectKey { object_type, id },
        })
    }
}

macro_rules! object_key_requests {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name(pub(crate) ObjectKeyRequest);
        impl Decode<'_> for $name {
            fn decode(reader: &mut Reader<'_>) -> Result<Self> {
                Ok(Self(ObjectKeyRequest::decode(reader)?))
            }
        }
    )+};
}

object_key_requests!(GetObjectInfoRequest, DeleteObjectRequest);

#[derive(Clone, Copy, Debug)]
pub(crate) struct GetPublicKeyRequest {
    pub(crate) id: u16,
    pub(crate) object_type: ObjectType,
}

impl Decode<'_> for GetPublicKeyRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let id = reader.read_u16()?;
        let object_type = match reader.remaining_len() {
            0 => ObjectType::AsymmetricKey,
            1 => ObjectType::from_byte(reader.read_u8()?).ok_or(DeviceError::InvalidData)?,
            _ => return Err(DeviceError::WrongLength),
        };
        Ok(Self { id, object_type })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SetOptionRequest<'a> {
    pub(crate) option: u8,
    pub(crate) values: &'a [u8],
}

impl<'a> Decode<'a> for SetOptionRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        let option = reader.read_u8()?;
        let values = reader.read_u16_sized_slice()?;
        Ok(Self { option, values })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ObjectHeader<'a> {
    pub(crate) requested_id: u16,
    pub(crate) label: &'a [u8; 40],
    pub(crate) domains: u16,
    pub(crate) capabilities: CapabilitySet,
    pub(crate) algorithm: u8,
}

impl<'a> Decode<'a> for ObjectHeader<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            requested_id: reader.read_u16()?,
            label: reader.read_array()?,
            domains: reader.read_u16()?,
            capabilities: CapabilitySet::from_bytes(*reader.read_array()?),
            algorithm: reader.read_u8()?,
        })
    }
}

macro_rules! object_requests {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name<'a> {
            pub(crate) header: ObjectHeader<'a>,
            pub(crate) material: &'a [u8],
        }
        impl<'a> Decode<'a> for $name<'a> {
            fn decode(reader: &mut Reader<'a>) -> Result<Self> {
                Ok(Self { header: ObjectHeader::decode(reader)?, material: reader.read_remainder() })
            }
        }
    )+};
}

object_requests!(
    PutOpaqueRequest,
    PutAsymmetricKeyRequest,
    GenerateAsymmetricKeyRequest,
    PutHmacKeyRequest,
    GenerateHmacKeyRequest,
    PutSymmetricKeyRequest,
    GenerateSymmetricKeyRequest,
    PutTemplateRequest,
);

#[derive(Clone, Copy, Debug)]
pub(crate) struct DelegatedObjectRequest<'a> {
    pub(crate) header: ObjectHeader<'a>,
    pub(crate) delegated_capabilities: CapabilitySet,
    pub(crate) material: &'a [u8],
}

impl<'a> Decode<'a> for DelegatedObjectRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            header: ObjectHeader::decode(reader)?,
            delegated_capabilities: CapabilitySet::from_bytes(*reader.read_array()?),
            material: reader.read_remainder(),
        })
    }
}

macro_rules! delegated_object_requests {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name<'a>(pub(crate) DelegatedObjectRequest<'a>);
        impl<'a> Decode<'a> for $name<'a> {
            fn decode(reader: &mut Reader<'a>) -> Result<Self> {
                Ok(Self(DelegatedObjectRequest::decode(reader)?))
            }
        }
    )+};
}

delegated_object_requests!(
    PutAuthenticationKeyRequest,
    PutWrapKeyRequest,
    GenerateWrapKeyRequest,
    PutPublicWrapKeyRequest,
);

#[derive(Clone, Copy, Debug)]
pub(crate) struct OtpAeadKeyRequest<'a> {
    pub(crate) header: ObjectHeader<'a>,
    pub(crate) nonce_id: &'a [u8; 4],
    pub(crate) material: &'a [u8],
}

impl<'a> Decode<'a> for OtpAeadKeyRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            header: ObjectHeader::decode(reader)?,
            nonce_id: reader.read_array()?,
            material: reader.read_remainder(),
        })
    }
}

macro_rules! otp_key_requests {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name<'a>(pub(crate) OtpAeadKeyRequest<'a>);
        impl<'a> Decode<'a> for $name<'a> {
            fn decode(reader: &mut Reader<'a>) -> Result<Self> { Ok(Self(OtpAeadKeyRequest::decode(reader)?)) }
        }
    )+};
}

otp_key_requests!(PutOtpAeadKeyRequest, GenerateOtpAeadKeyRequest);

#[derive(Clone, Copy, Debug)]
pub(crate) struct SignPssRequest<'a> {
    pub(crate) id: u16,
    pub(crate) mgf_hash: u8,
    pub(crate) salt_length: u16,
    pub(crate) digest: &'a [u8],
}

impl<'a> Decode<'a> for SignPssRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            id: reader.read_u16()?,
            mgf_hash: reader.read_u8()?,
            salt_length: reader.read_u16()?,
            digest: reader.read_remainder(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SignMlDsaRequest<'a> {
    pub(crate) id: u16,
    pub(crate) mode: u8,
    pub(crate) context: &'a [u8],
    pub(crate) message: &'a [u8],
}

impl<'a> Decode<'a> for SignMlDsaRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        let id = reader.read_u16()?;
        let mode = reader.read_u8()?;
        let context = reader.read_u8_sized_slice()?;
        Ok(Self {
            id,
            mode,
            context,
            message: reader.read_remainder(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EncapsulateMlKemRequest {
    pub(crate) id: u16,
}
impl Decode<'_> for EncapsulateMlKemRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            id: reader.read_u16()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DeriveEcdhKdfRequest<'a> {
    pub(crate) id: u16,
    pub(crate) hash: u8,
    pub(crate) output_length: u16,
    pub(crate) peer_public: &'a [u8],
    pub(crate) prefix: &'a [u8],
    pub(crate) shared_info: &'a [u8],
}

impl<'a> Decode<'a> for DeriveEcdhKdfRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        let id = reader.read_u16()?;
        let hash = reader.read_u8()?;
        let output_length = reader.read_u16()?;
        let peer_length = usize::from(reader.read_u16()?);
        let prefix_length = usize::from(reader.read_u16()?);
        let info_length = usize::from(reader.read_u16()?);
        Ok(Self {
            id,
            hash,
            output_length,
            peer_public: reader.read_slice(peer_length)?,
            prefix: reader.read_slice(prefix_length)?,
            shared_info: reader.read_slice(info_length)?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionObjectRequest<'a> {
    pub(crate) operation: SessionObjectCommand,
    pub(crate) payload: &'a [u8],
}

impl<'a> Decode<'a> for SessionObjectRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            operation: SessionObjectCommand::from_byte(reader.read_u8()?)
                .ok_or(DeviceError::InvalidData)?,
            payload: reader.read_remainder(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DecryptOaepRequest<'a> {
    pub(crate) id: u16,
    pub(crate) mgf_hash: u8,
    pub(crate) ciphertext_and_label: &'a [u8],
}

impl<'a> Decode<'a> for DecryptOaepRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            id: reader.read_u16()?,
            mgf_hash: reader.read_u8()?,
            ciphertext_and_label: reader.read_remainder(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AesCbcRequest<'a> {
    pub(crate) id: u16,
    pub(crate) iv: &'a [u8; 16],
    pub(crate) input: &'a [u8],
}

impl<'a> Decode<'a> for AesCbcRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            id: reader.read_u16()?,
            iv: reader.read_array()?,
            input: reader.read_remainder(),
        })
    }
}

macro_rules! aes_cbc_requests {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name<'a>(pub(crate) AesCbcRequest<'a>);
        impl<'a> Decode<'a> for $name<'a> {
            fn decode(reader: &mut Reader<'a>) -> Result<Self> { Ok(Self(AesCbcRequest::decode(reader)?)) }
        }
    )+};
}

aes_cbc_requests!(EncryptCbcRequest, DecryptCbcRequest);

#[derive(Clone, Copy, Debug)]
pub(crate) struct ExportWrappedRequest {
    pub(crate) wrap_id: u16,
    pub(crate) target: ObjectKey,
    pub(crate) format: Option<u8>,
}

impl Decode<'_> for ExportWrappedRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let wrap_id = reader.read_u16()?;
        let object_type =
            ObjectType::from_byte(reader.read_u8()?).ok_or(DeviceError::InvalidData)?;
        let id = reader.read_u16()?;
        let format = match reader.remaining_len() {
            0 => None,
            1 => Some(reader.read_u8()?),
            _ => return Err(DeviceError::WrongLength),
        };
        Ok(Self {
            wrap_id,
            target: ObjectKey { object_type, id },
            format,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ImportWrappedRequest<'a> {
    pub(crate) wrap_id: u16,
    pub(crate) format: u8,
    pub(crate) nonce: &'a [u8; 13],
    pub(crate) ciphertext: &'a [u8],
}

impl<'a> Decode<'a> for ImportWrappedRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            wrap_id: reader.read_u16()?,
            format: reader.read_u8()?,
            nonce: reader.read_array()?,
            ciphertext: reader.read_remainder(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateOtpAeadRequest<'a> {
    pub(crate) id: u16,
    pub(crate) credential: &'a [u8; 22],
}
impl<'a> Decode<'a> for CreateOtpAeadRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            id: reader.read_u16()?,
            credential: reader.read_array()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DecryptOtpRequest<'a> {
    pub(crate) id: u16,
    pub(crate) aead: &'a [u8; 36],
    pub(crate) otp: &'a [u8; 16],
}
impl<'a> Decode<'a> for DecryptOtpRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            id: reader.read_u16()?,
            aead: reader.read_array()?,
            otp: reader.read_array()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RewrapOtpAeadRequest<'a> {
    pub(crate) from_id: u16,
    pub(crate) to_id: u16,
    pub(crate) aead: &'a [u8; 36],
}
impl<'a> Decode<'a> for RewrapOtpAeadRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            from_id: reader.read_u16()?,
            to_id: reader.read_u16()?,
            aead: reader.read_array()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SignAttestationCertificateRequest {
    pub(crate) target_id: u16,
    pub(crate) attesting_id: u16,
}
impl Decode<'_> for SignAttestationCertificateRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            target_id: reader.read_u16()?,
            attesting_id: reader.read_u16()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ChangeAuthenticationKeyRequest<'a> {
    pub(crate) id: u16,
    pub(crate) algorithm: u8,
    pub(crate) material: &'a [u8],
}
impl<'a> Decode<'a> for ChangeAuthenticationKeyRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            id: reader.read_u16()?,
            algorithm: reader.read_u8()?,
            material: reader.read_remainder(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ExportRsaWrappedFields<'a> {
    pub(crate) wrap_id: u16,
    pub(crate) target: ObjectKey,
    pub(crate) aes_algorithm: u8,
    pub(crate) oaep_hash: u8,
    pub(crate) mgf_hash: u8,
    pub(crate) label_hash: &'a [u8],
}

impl<'a> Decode<'a> for ExportRsaWrappedFields<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        let wrap_id = reader.read_u16()?;
        let object_type =
            ObjectType::from_byte(reader.read_u8()?).ok_or(DeviceError::InvalidData)?;
        let id = reader.read_u16()?;
        Ok(Self {
            wrap_id,
            target: ObjectKey { object_type, id },
            aes_algorithm: reader.read_u8()?,
            oaep_hash: reader.read_u8()?,
            mgf_hash: reader.read_u8()?,
            label_hash: reader.read_remainder(),
        })
    }
}

macro_rules! export_rsa_requests {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name<'a>(pub(crate) ExportRsaWrappedFields<'a>);
        impl<'a> Decode<'a> for $name<'a> {
            fn decode(reader: &mut Reader<'a>) -> Result<Self> { Ok(Self(ExportRsaWrappedFields::decode(reader)?)) }
        }
    )+};
}

export_rsa_requests!(GetRsaWrappedKeyRequest, ExportRsaWrappedRequest);

#[derive(Clone, Copy, Debug)]
pub(crate) struct ImportRsaWrappedRequest<'a> {
    pub(crate) wrap_id: u16,
    pub(crate) oaep_hash: u8,
    pub(crate) mgf_hash: u8,
    pub(crate) wrapped_and_label: &'a [u8],
}

impl<'a> Decode<'a> for ImportRsaWrappedRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            wrap_id: reader.read_u16()?,
            oaep_hash: reader.read_u8()?,
            mgf_hash: reader.read_u8()?,
            wrapped_and_label: reader.read_remainder(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PutRsaWrappedKeyRequest<'a> {
    pub(crate) wrap_id: u16,
    pub(crate) object_type: ObjectType,
    pub(crate) requested_id: u16,
    pub(crate) label: &'a [u8; 40],
    pub(crate) domains: u16,
    pub(crate) capabilities: CapabilitySet,
    pub(crate) algorithm: u8,
    pub(crate) oaep_hash: u8,
    pub(crate) mgf_hash: u8,
    pub(crate) wrapped_and_label: &'a [u8],
}

impl<'a> Decode<'a> for PutRsaWrappedKeyRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            wrap_id: reader.read_u16()?,
            object_type: ObjectType::from_byte(reader.read_u8()?)
                .ok_or(DeviceError::InvalidData)?,
            requested_id: reader.read_u16()?,
            label: reader.read_array()?,
            domains: reader.read_u16()?,
            capabilities: CapabilitySet::from_bytes(*reader.read_array()?),
            algorithm: reader.read_u8()?,
            oaep_hash: reader.read_u8()?,
            mgf_hash: reader.read_u8()?,
            wrapped_and_label: reader.read_remainder(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum SessionSourceRequest {
    Volatile(u64),
    PersistentAsymmetric(u16),
    PersistentSymmetric(u16),
}

impl Decode<'_> for SessionSourceRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        match reader.read_u8()? {
            0 => Ok(Self::Volatile(reader.read_u64()?)),
            1 => Ok(Self::PersistentAsymmetric(reader.read_u16()?)),
            2 => Ok(Self::PersistentSymmetric(reader.read_u16()?)),
            _ => Err(DeviceError::InvalidData),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionResultHeader {
    pub(crate) flags: u8,
    pub(crate) kind: SessionObjectKind,
    pub(crate) output_length: u16,
}

impl Decode<'_> for SessionResultHeader {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            flags: reader.read_u8()?,
            kind: SessionObjectKind::from_byte(reader.read_u8()?)
                .ok_or(DeviceError::InvalidData)?,
            output_length: reader.read_u16()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct GenerateSessionAsymmetricKeyRequest {
    pub(crate) flags: u8,
    pub(crate) algorithm: u8,
}
impl Decode<'_> for GenerateSessionAsymmetricKeyRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            flags: reader.read_u8()?,
            algorithm: reader.read_u8()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DeriveSessionEcdhRequest<'a> {
    pub(crate) header: SessionResultHeader,
    pub(crate) source: SessionSourceRequest,
    pub(crate) peer_public: &'a [u8],
}
impl<'a> Decode<'a> for DeriveSessionEcdhRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            header: SessionResultHeader::decode(reader)?,
            source: SessionSourceRequest::decode(reader)?,
            peer_public: reader.read_u16_sized_slice()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ConcatenateSessionKeysRequest {
    pub(crate) header: SessionResultHeader,
    pub(crate) left: u64,
    pub(crate) right: u64,
}
impl Decode<'_> for ConcatenateSessionKeysRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            header: SessionResultHeader::decode(reader)?,
            left: reader.read_u64()?,
            right: reader.read_u64()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ConcatenateSessionDataRequest<'a> {
    pub(crate) header: SessionResultHeader,
    pub(crate) base: u64,
    pub(crate) data: &'a [u8],
}
impl<'a> Decode<'a> for ConcatenateSessionDataRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            header: SessionResultHeader::decode(reader)?,
            base: reader.read_u64()?,
            data: reader.read_remainder(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ExtractSessionObjectRequest {
    pub(crate) header: SessionResultHeader,
    pub(crate) base: u64,
    pub(crate) offset: u16,
}
impl Decode<'_> for ExtractSessionObjectRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            header: SessionResultHeader::decode(reader)?,
            base: reader.read_u64()?,
            offset: reader.read_u16()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Sha256SessionObjectRequest {
    pub(crate) header: SessionResultHeader,
    pub(crate) base: u64,
}
impl Decode<'_> for Sha256SessionObjectRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            header: SessionResultHeader::decode(reader)?,
            base: reader.read_u64()?,
        })
    }
}

#[derive(Clone)]
pub(crate) struct CounterKdfSessionObjectRequest<'a> {
    pub(crate) header: SessionResultHeader,
    pub(crate) source: SessionSourceRequest,
    pub(crate) fields: Vec<CounterKdfField<'a>>,
}
impl<'a> Decode<'a> for CounterKdfSessionObjectRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        let header = SessionResultHeader::decode(reader)?;
        let source = SessionSourceRequest::decode(reader)?;
        let count = usize::from(reader.read_u8()?);
        if !(1..=64).contains(&count) {
            return Err(DeviceError::InvalidData);
        }
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = reader.read_u8()?;
            match kind {
                0 => {
                    let value = reader.read_u16_sized_slice()?;
                    if value.is_empty() {
                        return Err(DeviceError::WrongLength);
                    }
                    fields.push(CounterKdfField::Bytes(value));
                }
                1 | 2 => {
                    let width_bits = reader.read_u8()?;
                    let little_endian = match reader.read_u8()? {
                        0 => false,
                        1 => true,
                        _ => return Err(DeviceError::InvalidData),
                    };
                    let format = IntegerFormat {
                        width_bits,
                        little_endian,
                    };
                    if kind == 1 {
                        fields.push(CounterKdfField::Counter(format));
                    } else {
                        let method = match reader.read_u8()? {
                            0 => LengthMethod::Key,
                            1 => LengthMethod::Segments,
                            _ => return Err(DeviceError::InvalidData),
                        };
                        fields.push(CounterKdfField::Length(format, method));
                    }
                }
                _ => return Err(DeviceError::InvalidData),
            }
        }
        Ok(Self {
            header,
            source,
            fields,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadSessionObjectRequest {
    pub(crate) handle: u64,
}
impl Decode<'_> for ReadSessionObjectRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            handle: reader.read_u64()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DeleteSessionObjectRequest {
    pub(crate) handle: u64,
}
impl Decode<'_> for DeleteSessionObjectRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            handle: reader.read_u64()?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct VerifySessionCmacRequest<'a> {
    pub(crate) handle: u64,
    pub(crate) signature: &'a [u8],
    pub(crate) message: &'a [u8],
}
impl<'a> Decode<'a> for VerifySessionCmacRequest<'a> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self> {
        let handle = reader.read_u64()?;
        let signature = reader.read_u8_sized_slice()?;
        Ok(Self {
            handle,
            signature,
            message: reader.read_remainder(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{DeriveEcdhKdfRequest, PutOpaqueRequest, SetOptionRequest};
    use crate::{CapabilitySet, DeviceError, wire::decode};

    #[test]
    fn object_request_decodes_header_and_borrows_material() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&0x1234_u16.to_be_bytes());
        encoded.extend_from_slice(&[b'l'; 40]);
        encoded.extend_from_slice(&0x8001_u16.to_be_bytes());
        encoded.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]);
        encoded.push(30);
        encoded.extend_from_slice(b"payload");

        let request = decode::<PutOpaqueRequest>(&encoded).unwrap();
        assert_eq!(request.header.requested_id, 0x1234);
        assert_eq!(request.header.label, &[b'l'; 40]);
        assert_eq!(request.header.domains, 0x8001);
        assert_eq!(
            request.header.capabilities,
            CapabilitySet::from_bytes([0, 0, 0, 0, 0, 0, 0, 5])
        );
        assert_eq!(request.header.algorithm, 30);
        assert_eq!(request.material, b"payload");
        assert_eq!(request.material.as_ptr(), encoded[53..].as_ptr());
    }

    #[test]
    fn length_prefixed_fields_leave_trailing_data_for_the_boundary_check() {
        let request = decode::<SetOptionRequest>(&[3, 0, 2, 7, 8]).unwrap();
        assert_eq!(request.option, 3);
        assert_eq!(request.values, &[7, 8]);
        assert_eq!(
            decode::<SetOptionRequest>(&[3, 0, 1, 7, 8]).err(),
            Some(DeviceError::WrongLength)
        );
    }

    #[test]
    fn compound_lengths_are_checked_without_allocating() {
        let encoded = [
            0, 9, // key id
            3, // SHA-256
            0, 32, // output length
            0, 3, // peer length
            0, 2, // prefix length
            0, 1, // info length
            1, 2, 3, 4, 5, 6,
        ];
        let request = decode::<DeriveEcdhKdfRequest>(&encoded).unwrap();
        assert_eq!(request.id, 9);
        assert_eq!(request.peer_public, &[1, 2, 3]);
        assert_eq!(request.prefix, &[4, 5]);
        assert_eq!(request.shared_info, &[6]);
        assert_eq!(
            decode::<DeriveEcdhKdfRequest>(&encoded[..encoded.len() - 1]).err(),
            Some(DeviceError::WrongLength)
        );
    }
}
