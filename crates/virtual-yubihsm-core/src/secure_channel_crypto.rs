use crate::{DeviceError, Result};
#[cfg(test)]
use software_key_core::secure_channel::scp03_kdf as shared_scp03_kdf;
use software_key_core::{
    secure_channel::{pad_iso7816, unpad_iso7816},
    software_symmetric::{
        aes_cmac, decrypt_aes_cbc, encrypt_aes_block, encrypt_aes_cbc, SoftwareSymmetricError,
        AES_BLOCK_SIZE,
    },
};

pub(crate) const BLOCK_SIZE: usize = AES_BLOCK_SIZE;

fn map_symmetric_error(error: SoftwareSymmetricError) -> DeviceError {
    match error {
        SoftwareSymmetricError::InvalidDataLength | SoftwareSymmetricError::InvalidIvLength => {
            DeviceError::WrongLength
        }
        SoftwareSymmetricError::InvalidKeyLength | SoftwareSymmetricError::AuthenticationFailed => {
            DeviceError::InvalidData
        }
    }
}

pub(crate) fn cmac(key: &[u8], data: &[u8]) -> Result<[u8; BLOCK_SIZE]> {
    aes_cmac(key, data).map_err(map_symmetric_error)
}

pub(crate) fn encrypt_block(key: &[u8], input: &[u8; BLOCK_SIZE]) -> Result<[u8; BLOCK_SIZE]> {
    encrypt_aes_block(key, input).map_err(map_symmetric_error)
}

pub(crate) fn cbc_encrypt(key: &[u8], iv: &[u8; BLOCK_SIZE], data: &[u8]) -> Result<Vec<u8>> {
    encrypt_aes_cbc(key, iv, data).map_err(map_symmetric_error)
}

pub(crate) fn cbc_decrypt(key: &[u8], iv: &[u8; BLOCK_SIZE], data: &[u8]) -> Result<Vec<u8>> {
    decrypt_aes_cbc(key, iv, data).map_err(map_symmetric_error)
}

pub(crate) fn pad(data: &[u8]) -> Vec<u8> {
    pad_iso7816(data)
}

pub(crate) fn unpad(data: Vec<u8>) -> Result<Vec<u8>> {
    unpad_iso7816(data).map_err(|_| DeviceError::InvalidData)
}

#[cfg(test)]
pub(crate) fn scp03_kdf(
    key: &[u8],
    constant: u8,
    context: &[u8],
    output_bits: u16,
) -> Result<Vec<u8>> {
    shared_scp03_kdf(key, constant, context, output_bits).map_err(|_| DeviceError::InvalidData)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_round_trip() {
        for length in 0..64 {
            let clear = vec![0x5a; length];
            assert_eq!(unpad(pad(&clear)).unwrap(), clear);
        }
    }
}
