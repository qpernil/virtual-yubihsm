use software_key_core::software_signing::{
    EcCurve, KeyKind, SoftwarePublicKey, SoftwareSigningKey,
};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const MAX_SESSION_OBJECTS: usize = 64;
pub(crate) const FLAG_READABLE: u8 = 1 << 0;
pub(crate) const FLAG_DERIVE: u8 = 1 << 1;
pub(crate) const FLAG_VERIFY: u8 = 1 << 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SessionObjectKind {
    GenericSecret = 1,
    Aes = 2,
    P256Private = 3,
}

impl SessionObjectKind {
    pub(crate) fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::GenericSecret,
            2 => Self::Aes,
            3 => Self::P256Private,
            _ => return None,
        })
    }
}

#[derive(Debug)]
pub(crate) enum SessionObjectMaterial {
    Secret(Zeroizing<Vec<u8>>),
    P256Private(SoftwareSigningKey),
}

impl Drop for SessionObjectMaterial {
    fn drop(&mut self) {
        if let Self::Secret(value) = self {
            value.zeroize();
        }
    }
}

#[derive(Debug)]
pub(crate) struct SessionObject {
    pub(crate) kind: SessionObjectKind,
    pub(crate) flags: u8,
    pub(crate) material: SessionObjectMaterial,
}

impl SessionObject {
    pub(crate) fn secret(
        kind: SessionObjectKind,
        flags: u8,
        value: Zeroizing<Vec<u8>>,
    ) -> Option<Self> {
        if value.is_empty()
            || value.len() > 1024
            || (kind == SessionObjectKind::Aes && !matches!(value.len(), 16 | 24 | 32))
            || kind == SessionObjectKind::P256Private
        {
            return None;
        }
        Some(Self {
            kind,
            flags,
            material: SessionObjectMaterial::Secret(value),
        })
    }

    pub(crate) fn p256_private(flags: u8, key: SoftwareSigningKey) -> Option<Self> {
        if key.key_kind() != KeyKind::Ec(EcCurve::P256) {
            return None;
        }
        Some(Self {
            kind: SessionObjectKind::P256Private,
            flags,
            material: SessionObjectMaterial::P256Private(key),
        })
    }

    pub(crate) fn secret_value(&self) -> Option<&[u8]> {
        match &self.material {
            SessionObjectMaterial::Secret(value) => Some(value),
            SessionObjectMaterial::P256Private(_) => None,
        }
    }

    pub(crate) fn p256_key(&self) -> Option<&SoftwareSigningKey> {
        match &self.material {
            SessionObjectMaterial::P256Private(key) => Some(key),
            SessionObjectMaterial::Secret(_) => None,
        }
    }

    pub(crate) fn public_key(&self) -> Option<Vec<u8>> {
        let SoftwarePublicKey::Ec { uncompressed, .. } = self.p256_key()?.public_key() else {
            return None;
        };
        Some(uncompressed)
    }
}

#[derive(Debug, Default)]
pub(crate) struct SessionObjects(BTreeMap<u64, SessionObject>);

impl SessionObjects {
    pub(crate) fn get(&self, handle: u64) -> Option<&SessionObject> {
        self.0.get(&handle)
    }

    pub(crate) fn insert(&mut self, object: SessionObject) -> Option<u64> {
        if self.0.len() >= MAX_SESSION_OBJECTS {
            return None;
        }
        loop {
            let mut encoded = [0; 8];
            getrandom::fill(&mut encoded).ok()?;
            let handle = u64::from_be_bytes(encoded);
            if handle != 0 && !self.0.contains_key(&handle) {
                self.0.insert(handle, object);
                return Some(handle);
            }
        }
    }

    pub(crate) fn remove(&mut self, handle: u64) -> Option<SessionObject> {
        self.0.remove(&handle)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}
