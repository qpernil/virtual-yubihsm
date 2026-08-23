use crate::{DeviceError, Result};

pub const HEADER_LENGTH: usize = 3;
pub const MAX_DATA_LENGTH: usize = 3_133;
pub const RESPONSE_BIT: u8 = 0x80;
pub const ERROR_COMMAND: u8 = 0x7f;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub command: u8,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn new(command: u8, data: impl Into<Vec<u8>>) -> Result<Self> {
        let data = data.into();
        if data.len() > MAX_DATA_LENGTH {
            return Err(DeviceError::WrongLength);
        }
        Ok(Self { command, data })
    }

    pub fn parse(encoded: &[u8]) -> Result<Self> {
        if encoded.len() < HEADER_LENGTH {
            return Err(DeviceError::WrongLength);
        }
        let length = u16::from_be_bytes([encoded[1], encoded[2]]) as usize;
        if length > MAX_DATA_LENGTH || encoded.len() != HEADER_LENGTH + length {
            return Err(DeviceError::WrongLength);
        }
        Self::new(encoded[0], encoded[HEADER_LENGTH..].to_vec())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(HEADER_LENGTH + self.data.len());
        encoded.push(self.command);
        encoded.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.data);
        encoded
    }

    pub fn response(request_command: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            command: request_command | RESPONSE_BIT,
            data: data.into(),
        }
    }

    pub fn error(error: DeviceError) -> Self {
        Self {
            command: ERROR_COMMAND,
            data: vec![error as u8],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_uses_three_byte_header() {
        let frame = Frame::new(0x42, [1, 2, 3]).unwrap();
        assert_eq!(frame.encode(), [0x42, 0, 3, 1, 2, 3]);
        assert_eq!(Frame::parse(&frame.encode()).unwrap(), frame);
    }

    #[test]
    fn rejects_truncated_and_trailing_data() {
        assert_eq!(Frame::parse(&[1, 0]), Err(DeviceError::WrongLength));
        assert_eq!(Frame::parse(&[1, 0, 0, 2]), Err(DeviceError::WrongLength));
    }
}
