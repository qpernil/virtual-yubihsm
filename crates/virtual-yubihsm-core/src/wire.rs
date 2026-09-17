use crate::{DeviceError, Result};

/// A request type decoded from the compact YubiHSM wire representation.
///
/// Implementations consume exactly the fields owned by the type. Call
/// [`decode`] at a command boundary to reject trailing input consistently.
pub(crate) trait Decode<'a>: Sized {
    fn decode(reader: &mut Reader<'a>) -> Result<Self>;
}

/// Decode one complete command payload.
pub(crate) fn decode<'a, T: Decode<'a>>(encoded: &'a [u8]) -> Result<T> {
    let mut reader = Reader::new(encoded);
    let value = T::decode(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

/// Bounds-checked reader for the positional YubiHSM command encoding.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    pub(crate) const fn remaining_len(&self) -> usize {
        self.remaining.len()
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(*self.read_array()?))
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(*self.read_array()?))
    }

    pub(crate) fn read_u8_sized_slice(&mut self) -> Result<&'a [u8]> {
        let length = usize::from(self.read_u8()?);
        self.read_slice(length)
    }

    pub(crate) fn read_u16_sized_slice(&mut self) -> Result<&'a [u8]> {
        let length = usize::from(self.read_u16()?);
        self.read_slice(length)
    }

    pub(crate) fn read_array<const N: usize>(&mut self) -> Result<&'a [u8; N]> {
        self.read_slice(N)?
            .try_into()
            .map_err(|_| DeviceError::WrongLength)
    }

    pub(crate) fn read_slice(&mut self, length: usize) -> Result<&'a [u8]> {
        if self.remaining.len() < length {
            return Err(DeviceError::WrongLength);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    pub(crate) fn read_remainder(&mut self) -> &'a [u8] {
        let value = self.remaining;
        self.remaining = &[];
        value
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(DeviceError::WrongLength)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Decode, Reader, decode};
    use crate::DeviceError;

    #[derive(Debug, Eq, PartialEq)]
    struct Example<'a> {
        tag: u8,
        id: u16,
        value: &'a [u8],
    }

    impl<'a> Decode<'a> for Example<'a> {
        fn decode(reader: &mut Reader<'a>) -> crate::Result<Self> {
            Ok(Self {
                tag: reader.read_u8()?,
                id: reader.read_u16()?,
                value: reader.read_remainder(),
            })
        }
    }

    #[test]
    fn decodes_borrowed_fields_without_copying() {
        let encoded = [7, 0x12, 0x34, 5, 6];
        let request: Example<'_> = decode(&encoded).unwrap();
        assert_eq!(
            request,
            Example {
                tag: 7,
                id: 0x1234,
                value: &[5, 6]
            }
        );
        assert_eq!(request.value.as_ptr(), encoded[3..].as_ptr());
    }

    #[test]
    fn rejects_short_and_trailing_inputs() {
        let mut short = Reader::new(&[1]);
        assert_eq!(short.read_u16(), Err(DeviceError::WrongLength));

        struct OneByte;
        impl Decode<'_> for OneByte {
            fn decode(reader: &mut Reader<'_>) -> crate::Result<Self> {
                reader.read_u8()?;
                Ok(Self)
            }
        }
        assert!(decode::<OneByte>(&[1]).is_ok());
        assert_eq!(
            decode::<OneByte>(&[1, 2]).err(),
            Some(DeviceError::WrongLength)
        );
    }
}
