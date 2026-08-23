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
