/// The command and algorithm surface compiled into the virtual device.
///
/// Cargo features are additive. If more than one profile feature is selected,
/// the most capable selected profile wins. The two asymmetric profiles exist
/// only to exercise client fallback selection in tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareProfile {
    YubiHsm2,
    SecureChannel,
    Full,
    TestPrefixedEcdh,
    TestSessionObjects,
}

impl FirmwareProfile {
    pub const fn compiled() -> Self {
        if cfg!(feature = "firmware-full") {
            Self::Full
        } else if cfg!(feature = "firmware-secure-channel")
            || cfg!(all(
                feature = "test-firmware-prefixed-ecdh",
                feature = "test-firmware-session-objects"
            ))
        {
            Self::SecureChannel
        } else if cfg!(feature = "test-firmware-prefixed-ecdh") {
            Self::TestPrefixedEcdh
        } else if cfg!(feature = "test-firmware-session-objects") {
            Self::TestSessionObjects
        } else {
            Self::YubiHsm2
        }
    }

    pub const fn extended_curves(self) -> bool {
        matches!(self, Self::Full)
    }

    pub const fn post_quantum(self) -> bool {
        matches!(self, Self::Full)
    }

    pub const fn prefixed_ecdh(self) -> bool {
        matches!(
            self,
            Self::SecureChannel | Self::Full | Self::TestPrefixedEcdh
        )
    }

    pub const fn session_objects(self) -> bool {
        matches!(
            self,
            Self::SecureChannel | Self::Full | Self::TestSessionObjects
        )
    }

    pub const fn direct_rsa_wrap(self) -> bool {
        matches!(self, Self::Full)
    }
}
