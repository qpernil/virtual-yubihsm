use crate::{DeviceError, Result};
use aes::{
    cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use cmac::{Cmac, Mac};

pub(crate) const BLOCK_SIZE: usize = 16;

pub(crate) fn cmac(key: &[u8], data: &[u8]) -> Result<[u8; BLOCK_SIZE]> {
    let mut mac =
        <Cmac<Aes128> as Mac>::new_from_slice(key).map_err(|_| DeviceError::InvalidData)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

pub(crate) fn encrypt_block(key: &[u8], input: &[u8; BLOCK_SIZE]) -> Result<[u8; BLOCK_SIZE]> {
    let cipher = Aes128::new_from_slice(key).map_err(|_| DeviceError::InvalidData)?;
    let mut block = Block::<Aes128>::from(*input);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

pub(crate) fn cbc_encrypt(key: &[u8], iv: &[u8; BLOCK_SIZE], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % BLOCK_SIZE != 0 {
        return Err(DeviceError::WrongLength);
    }
    let cipher = Aes128::new_from_slice(key).map_err(|_| DeviceError::InvalidData)?;
    let mut previous = *iv;
    let mut output = Vec::with_capacity(data.len());
    for input in data.chunks_exact(BLOCK_SIZE) {
        let mut bytes = [0; BLOCK_SIZE];
        for (out, (left, right)) in bytes.iter_mut().zip(input.iter().zip(previous)) {
            *out = left ^ right;
        }
        let mut block = Block::<Aes128>::from(bytes);
        cipher.encrypt_block(&mut block);
        previous.copy_from_slice(&block);
        output.extend_from_slice(&block);
    }
    Ok(output)
}

pub(crate) fn cbc_decrypt(key: &[u8], iv: &[u8; BLOCK_SIZE], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % BLOCK_SIZE != 0 {
        return Err(DeviceError::WrongLength);
    }
    let cipher = Aes128::new_from_slice(key).map_err(|_| DeviceError::InvalidData)?;
    let mut previous = *iv;
    let mut output = Vec::with_capacity(data.len());
    for input in data.chunks_exact(BLOCK_SIZE) {
        let mut ciphertext = [0; BLOCK_SIZE];
        ciphertext.copy_from_slice(input);
        let mut block = Block::<Aes128>::from(ciphertext);
        cipher.decrypt_block(&mut block);
        for (byte, prior) in block.iter_mut().zip(previous) {
            *byte ^= prior;
        }
        output.extend_from_slice(&block);
        previous = ciphertext;
    }
    Ok(output)
}

pub(crate) fn pad(data: &[u8]) -> Vec<u8> {
    let length = (data.len() + 1).div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
    let mut output = Vec::with_capacity(length);
    output.extend_from_slice(data);
    output.push(0x80);
    output.resize(length, 0);
    output
}

pub(crate) fn unpad(mut data: Vec<u8>) -> Result<Vec<u8>> {
    let marker = data
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or(DeviceError::InvalidData)?;
    if data[marker] != 0x80 {
        return Err(DeviceError::InvalidData);
    }
    data.truncate(marker);
    Ok(data)
}

pub(crate) fn scp03_kdf(
    key: &[u8],
    constant: u8,
    context: &[u8],
    output_bits: u16,
) -> Result<Vec<u8>> {
    if output_bits == 0 || output_bits % 8 != 0 {
        return Err(DeviceError::InvalidData);
    }
    let output_length = usize::from(output_bits / 8);
    let iterations = output_length.div_ceil(BLOCK_SIZE);
    let mut output = Vec::with_capacity(iterations * BLOCK_SIZE);
    for counter in 1..=iterations {
        let mut input = Vec::with_capacity(16 + context.len());
        input.extend_from_slice(&[0; 11]);
        input.push(constant);
        input.push(0);
        input.extend_from_slice(&output_bits.to_be_bytes());
        input.push(counter as u8);
        input.extend_from_slice(context);
        output.extend_from_slice(&cmac(key, &input)?);
    }
    output.truncate(output_length);
    Ok(output)
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
