use serde::{Deserialize, Serialize};

/// Capability bit numbers from the YubiHSM 2 protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Capability {
    GetOpaque = 0x00,
    PutOpaque = 0x01,
    PutAuthenticationKey = 0x02,
    PutAsymmetricKey = 0x03,
    GenerateAsymmetricKey = 0x04,
    SignPkcs = 0x05,
    SignPss = 0x06,
    SignEcdsa = 0x07,
    SignEddsa = 0x08,
    DecryptPkcs = 0x09,
    DecryptOaep = 0x0a,
    DeriveEcdh = 0x0b,
    ExportWrapped = 0x0c,
    ImportWrapped = 0x0d,
    PutWrapKey = 0x0e,
    GenerateWrapKey = 0x0f,
    ExportableUnderWrap = 0x10,
    SetOption = 0x11,
    GetOption = 0x12,
    GetPseudoRandom = 0x13,
    PutMacKey = 0x14,
    GenerateHmacKey = 0x15,
    SignHmac = 0x16,
    VerifyHmac = 0x17,
    GetLogEntries = 0x18,
    SignSshCertificate = 0x19,
    GetTemplate = 0x1a,
    PutTemplate = 0x1b,
    ResetDevice = 0x1c,
    DecryptOtp = 0x1d,
    CreateOtpAead = 0x1e,
    RandomizeOtpAead = 0x1f,
    RewrapFromOtpAeadKey = 0x20,
    RewrapToOtpAeadKey = 0x21,
    SignAttestationCertificate = 0x22,
    PutOtpAeadKey = 0x23,
    GenerateOtpAeadKey = 0x24,
    WrapData = 0x25,
    UnwrapData = 0x26,
    DeleteOpaque = 0x27,
    DeleteAuthenticationKey = 0x28,
    DeleteAsymmetricKey = 0x29,
    DeleteWrapKey = 0x2a,
    DeleteHmacKey = 0x2b,
    DeleteTemplate = 0x2c,
    DeleteOtpAeadKey = 0x2d,
    ChangeAuthenticationKey = 0x2e,
    PutSymmetricKey = 0x2f,
    GenerateSymmetricKey = 0x30,
    DeleteSymmetricKey = 0x31,
    DecryptEcb = 0x32,
    EncryptEcb = 0x33,
    DecryptCbc = 0x34,
    EncryptCbc = 0x35,
    PutPublicWrapKey = 0x36,
    DeletePublicWrapKey = 0x37,
    /// Atomically augment an ECDH secret and pass it through a KDF.
    ///
    /// This is a virtual-device extension and is intentionally distinct from
    /// `DeriveEcdh`, which returns the raw ECDH result.
    DeriveEcdhKdf = 0x38,
}

/// The protocol's big-endian eight-byte capability bitmap.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CapabilitySet([u8; 8]);

impl CapabilitySet {
    pub const NONE: Self = Self([0; 8]);
    pub const ALL: Self = Self([0xff; 8]);

    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; 8] {
        self.0
    }

    pub fn from_capabilities(values: impl IntoIterator<Item = Capability>) -> Self {
        let mut result = Self::NONE;
        for value in values {
            result.insert(value);
        }
        result
    }

    pub fn contains(self, capability: Capability) -> bool {
        let bit = capability as usize;
        self.0[7 - bit / 8] & (1 << (bit % 8)) != 0
    }

    pub fn contains_all(self, required: Self) -> bool {
        self.0
            .iter()
            .zip(required.0)
            .all(|(available, required)| available & required == required)
    }

    pub fn is_subset_of(self, available: Self) -> bool {
        available.contains_all(self)
    }

    pub fn insert(&mut self, capability: Capability) {
        let bit = capability as usize;
        self.0[7 - bit / 8] |= 1 << (bit % 8);
    }

    pub fn intersection(self, other: Self) -> Self {
        let mut bytes = [0; 8];
        for (output, (left, right)) in bytes.iter_mut().zip(self.0.into_iter().zip(other.0)) {
            *output = left & right;
        }
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_official_big_endian_bit_layout() {
        let capabilities = CapabilitySet::from_capabilities([
            Capability::GetOpaque,
            Capability::SignEcdsa,
            Capability::DeletePublicWrapKey,
        ]);
        assert_eq!(capabilities.to_bytes(), [0, 0x80, 0, 0, 0, 0, 0, 0x81]);
        assert!(capabilities.contains(Capability::SignEcdsa));
        assert!(!capabilities.contains(Capability::SignPss));
    }
}
