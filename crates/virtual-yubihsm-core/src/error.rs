use core::fmt;

pub type Result<T> = core::result::Result<T, DeviceError>;

/// Errors returned by the YubiHSM wire protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DeviceError {
    InvalidCommand = 0x01,
    InvalidData = 0x02,
    InvalidSession = 0x03,
    AuthenticationFailed = 0x04,
    SessionsFull = 0x05,
    SessionFailed = 0x06,
    StorageFailed = 0x07,
    WrongLength = 0x08,
    InsufficientPermissions = 0x09,
    LogFull = 0x0a,
    ObjectNotFound = 0x0b,
    InvalidId = 0x0c,
    SshCaConstraintViolation = 0x0e,
    InvalidOtp = 0x0f,
    DemoMode = 0x10,
    ObjectExists = 0x11,
}

impl DeviceError {
    /// Decode an error byte returned in a YubiHSM error frame.
    pub fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0x01 => Self::InvalidCommand,
            0x02 => Self::InvalidData,
            0x03 => Self::InvalidSession,
            0x04 => Self::AuthenticationFailed,
            0x05 => Self::SessionsFull,
            0x06 => Self::SessionFailed,
            0x07 => Self::StorageFailed,
            0x08 => Self::WrongLength,
            0x09 => Self::InsufficientPermissions,
            0x0a => Self::LogFull,
            0x0b => Self::ObjectNotFound,
            0x0c => Self::InvalidId,
            0x0e => Self::SshCaConstraintViolation,
            0x0f => Self::InvalidOtp,
            0x10 => Self::DemoMode,
            0x11 => Self::ObjectExists,
            _ => return None,
        })
    }
}

impl fmt::Display for DeviceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCommand => "invalid command",
            Self::InvalidData => "invalid data",
            Self::InvalidSession => "invalid session",
            Self::AuthenticationFailed => "authentication failed",
            Self::SessionsFull => "sessions full",
            Self::SessionFailed => "session failed",
            Self::StorageFailed => "storage failed",
            Self::WrongLength => "wrong length",
            Self::InsufficientPermissions => "insufficient permissions",
            Self::LogFull => "log full",
            Self::ObjectNotFound => "object not found",
            Self::InvalidId => "invalid object id",
            Self::SshCaConstraintViolation => "SSH CA constraint violation",
            Self::InvalidOtp => "invalid OTP",
            Self::DemoMode => "demo mode",
            Self::ObjectExists => "object already exists",
        })
    }
}

impl std::error::Error for DeviceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_wire_error_values() {
        assert_eq!(
            DeviceError::from_byte(0x01),
            Some(DeviceError::InvalidCommand)
        );
        assert_eq!(
            DeviceError::from_byte(0x11),
            Some(DeviceError::ObjectExists)
        );
        assert_eq!(DeviceError::from_byte(0x0d), None);
    }
}
