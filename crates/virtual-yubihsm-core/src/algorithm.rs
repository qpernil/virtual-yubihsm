/// Algorithm identifiers from the YubiHSM 2 protocol.
///
/// `X25519` and `EcdhKdf` are virtual-device extensions. The official registry
/// currently ends at `AesKwp`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    RsaPkcs1Sha1 = 1,
    RsaPkcs1Sha256 = 2,
    RsaPkcs1Sha384 = 3,
    RsaPkcs1Sha512 = 4,
    RsaPssSha1 = 5,
    RsaPssSha256 = 6,
    RsaPssSha384 = 7,
    RsaPssSha512 = 8,
    Rsa2048 = 9,
    Rsa3072 = 10,
    Rsa4096 = 11,
    EcP256 = 12,
    EcP384 = 13,
    EcP521 = 14,
    EcK256 = 15,
    EcBrainpoolP256 = 16,
    EcBrainpoolP384 = 17,
    EcBrainpoolP512 = 18,
    HmacSha1 = 19,
    HmacSha256 = 20,
    HmacSha384 = 21,
    HmacSha512 = 22,
    EcdsaSha1 = 23,
    Ecdh = 24,
    RsaOaepSha1 = 25,
    RsaOaepSha256 = 26,
    RsaOaepSha384 = 27,
    RsaOaepSha512 = 28,
    Aes128CcmWrap = 29,
    OpaqueData = 30,
    OpaqueX509Certificate = 31,
    Mgf1Sha1 = 32,
    Mgf1Sha256 = 33,
    Mgf1Sha384 = 34,
    Mgf1Sha512 = 35,
    TemplateSsh = 36,
    Aes128YubicoOtp = 37,
    Aes128YubicoAuthentication = 38,
    Aes192YubicoOtp = 39,
    Aes256YubicoOtp = 40,
    Aes192CcmWrap = 41,
    Aes256CcmWrap = 42,
    EcdsaSha256 = 43,
    EcdsaSha384 = 44,
    EcdsaSha512 = 45,
    Ed25519 = 46,
    EcP224 = 47,
    RsaPkcs1Decrypt = 48,
    EcP256YubicoAuthentication = 49,
    Aes128 = 50,
    Aes192 = 51,
    Aes256 = 52,
    AesEcb = 53,
    AesCbc = 54,
    AesKwp = 55,
    X25519 = 56,
    /// Support for the virtual `DeriveEcdhKdf` command.
    EcdhKdf = 57,
}

impl Algorithm {
    pub const OFFICIAL: [Self; 55] = [
        Self::RsaPkcs1Sha1,
        Self::RsaPkcs1Sha256,
        Self::RsaPkcs1Sha384,
        Self::RsaPkcs1Sha512,
        Self::RsaPssSha1,
        Self::RsaPssSha256,
        Self::RsaPssSha384,
        Self::RsaPssSha512,
        Self::Rsa2048,
        Self::Rsa3072,
        Self::Rsa4096,
        Self::EcP256,
        Self::EcP384,
        Self::EcP521,
        Self::EcK256,
        Self::EcBrainpoolP256,
        Self::EcBrainpoolP384,
        Self::EcBrainpoolP512,
        Self::HmacSha1,
        Self::HmacSha256,
        Self::HmacSha384,
        Self::HmacSha512,
        Self::EcdsaSha1,
        Self::Ecdh,
        Self::RsaOaepSha1,
        Self::RsaOaepSha256,
        Self::RsaOaepSha384,
        Self::RsaOaepSha512,
        Self::Aes128CcmWrap,
        Self::OpaqueData,
        Self::OpaqueX509Certificate,
        Self::Mgf1Sha1,
        Self::Mgf1Sha256,
        Self::Mgf1Sha384,
        Self::Mgf1Sha512,
        Self::TemplateSsh,
        Self::Aes128YubicoOtp,
        Self::Aes128YubicoAuthentication,
        Self::Aes192YubicoOtp,
        Self::Aes256YubicoOtp,
        Self::Aes192CcmWrap,
        Self::Aes256CcmWrap,
        Self::EcdsaSha256,
        Self::EcdsaSha384,
        Self::EcdsaSha512,
        Self::Ed25519,
        Self::EcP224,
        Self::RsaPkcs1Decrypt,
        Self::EcP256YubicoAuthentication,
        Self::Aes128,
        Self::Aes192,
        Self::Aes256,
        Self::AesEcb,
        Self::AesCbc,
        Self::AesKwp,
    ];

    pub const fn from_byte(value: u8) -> Option<Self> {
        if value == 0 || value > Self::EcdhKdf as u8 {
            return None;
        }
        // SAFETY: every value in the inclusive range 1..=57 is represented.
        Some(unsafe { core::mem::transmute::<u8, Self>(value) })
    }

    pub const fn is_rsa_key(self) -> bool {
        matches!(self, Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096)
    }

    pub const fn is_weierstrass_key(self) -> bool {
        matches!(
            self,
            Self::EcP224
                | Self::EcP256
                | Self::EcP384
                | Self::EcP521
                | Self::EcK256
                | Self::EcBrainpoolP256
                | Self::EcBrainpoolP384
                | Self::EcBrainpoolP512
        )
    }

    /// Serialized private-key material length used by protocol imports and the
    /// software crypto backend.
    pub const fn asymmetric_key_length(self) -> Option<usize> {
        match self {
            Self::Rsa2048 => Some(256),
            Self::Rsa3072 => Some(384),
            Self::Rsa4096 => Some(512),
            Self::EcP224 => Some(28),
            Self::EcP256 | Self::EcK256 | Self::EcBrainpoolP256 | Self::Ed25519 | Self::X25519 => {
                Some(32)
            }
            Self::EcP384 | Self::EcBrainpoolP384 => Some(48),
            Self::EcP521 => Some(66),
            Self::EcBrainpoolP512 => Some(64),
            _ => None,
        }
    }

    /// Object size reported by a physical YubiHSM through `GetObjectInfo`.
    /// This is metadata only and must not be used as a key or wire length.
    pub const fn asymmetric_object_length(self) -> Option<usize> {
        match self {
            Self::Rsa2048 => Some(896),
            Self::Rsa3072 => Some(1_344),
            Self::Rsa4096 => Some(1_792),
            Self::EcP224 => Some(84),
            Self::EcP256 | Self::EcK256 | Self::EcBrainpoolP256 => Some(96),
            Self::EcP384 | Self::EcBrainpoolP384 => Some(144),
            Self::EcP521 => Some(198),
            Self::EcBrainpoolP512 => Some(192),
            Self::Ed25519 => Some(128),
            Self::X25519 => Some(64),
            _ => None,
        }
    }

    /// Object size reported by a physical YubiHSM through `GetObjectInfo`.
    pub const fn hmac_object_length(self) -> Option<usize> {
        match self {
            Self::HmacSha1 | Self::HmacSha256 => Some(128),
            Self::HmacSha384 | Self::HmacSha512 => Some(256),
            _ => None,
        }
    }

    pub const fn aes_key_length(self) -> Option<usize> {
        match self {
            Self::Aes128 | Self::Aes128CcmWrap | Self::Aes128YubicoOtp => Some(16),
            Self::Aes192 | Self::Aes192CcmWrap | Self::Aes192YubicoOtp => Some(24),
            Self::Aes256 | Self::Aes256CcmWrap | Self::Aes256YubicoOtp => Some(32),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_registry_is_contiguous_and_x25519_is_the_first_extension() {
        assert_eq!(Algorithm::OFFICIAL.len(), 55);
        for (index, algorithm) in Algorithm::OFFICIAL.into_iter().enumerate() {
            assert_eq!(algorithm as usize, index + 1);
            assert_eq!(Algorithm::from_byte(algorithm as u8), Some(algorithm));
        }
        assert_eq!(Algorithm::X25519 as u8, 56);
        assert_eq!(Algorithm::from_byte(56), Some(Algorithm::X25519));
        assert_eq!(Algorithm::from_byte(57), Some(Algorithm::EcdhKdf));
        assert_eq!(Algorithm::from_byte(58), None);
    }

    #[test]
    fn asymmetric_wire_material_and_internal_object_sizes_are_distinct() {
        for (algorithm, material_length, object_length) in [
            (Algorithm::Rsa2048, 256, 896),
            (Algorithm::Rsa3072, 384, 1_344),
            (Algorithm::Rsa4096, 512, 1_792),
            (Algorithm::EcP224, 28, 84),
            (Algorithm::EcP256, 32, 96),
            (Algorithm::EcP384, 48, 144),
            (Algorithm::EcP521, 66, 198),
            (Algorithm::EcBrainpoolP512, 64, 192),
            (Algorithm::Ed25519, 32, 128),
            (Algorithm::X25519, 32, 64),
        ] {
            assert_eq!(algorithm.asymmetric_key_length(), Some(material_length));
            assert_eq!(algorithm.asymmetric_object_length(), Some(object_length));
        }
    }
}
