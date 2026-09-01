use crate::{
    DeviceError, Frame, Result, SessionAuthorization,
    frame::{HEADER_LENGTH, MAX_DATA_LENGTH},
    secure_channel_crypto::{
        BLOCK_SIZE, cbc_decrypt, cbc_encrypt, cmac, encrypt_block, pad, unpad,
    },
};
use software_key_core::{
    secure_channel::{scp03_cryptogram, scp03_key, x963_kdf_sha256},
    software_key_agreement::derive_with_signing_key,
    software_signing::{EcCurve, KeyKind, SoftwarePublicKey, SoftwareSigningKey},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const MAC_LENGTH: usize = 8;
pub(crate) const CHALLENGE_LENGTH: usize = 8;
pub(crate) const P256_PUBLIC_KEY_LENGTH: usize = 65;
pub(crate) const AUTHENTICATION_ALGORITHM_AES128_YUBICO: u8 = 38;
pub(crate) const AUTHENTICATION_ALGORITHM_EC_P256: u8 = 49;
const SCP11_SHARED_INFO: [u8; 3] = [0x3c, 0x88, 0x10];

pub(crate) fn secure_response_data_fits(data_length: usize) -> bool {
    let Some(padded_length) = HEADER_LENGTH
        .checked_add(data_length)
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.div_ceil(BLOCK_SIZE).checked_mul(BLOCK_SIZE))
    else {
        return false;
    };
    1_usize
        .checked_add(padded_length)
        .and_then(|length| length.checked_add(MAC_LENGTH))
        .is_some_and(|length| length <= MAX_DATA_LENGTH)
}

pub(crate) fn secure_response_fits(response: &Frame) -> bool {
    secure_response_data_fits(response.data.len())
}

#[derive(Debug)]
pub(crate) struct SessionEntry {
    pub(crate) authorization: SessionAuthorization,
    pub(crate) secure: SecureSession,
    pub(crate) expected_host_cryptogram: Option<[u8; MAC_LENGTH]>,
    pub(crate) authenticated: bool,
}

#[derive(Debug)]
pub(crate) struct SecureSession {
    sid: u8,
    s_enc: Zeroizing<[u8; BLOCK_SIZE]>,
    s_mac: Zeroizing<[u8; BLOCK_SIZE]>,
    s_rmac: Zeroizing<[u8; BLOCK_SIZE]>,
    counter: [u8; BLOCK_SIZE],
    mac_chaining_value: [u8; BLOCK_SIZE],
}

impl SecureSession {
    pub(crate) fn begin_symmetric(
        sid: u8,
        static_keys: &[u8],
        host_challenge: &[u8],
        card_challenge: [u8; CHALLENGE_LENGTH],
    ) -> Result<(Self, [u8; MAC_LENGTH], [u8; MAC_LENGTH])> {
        if static_keys.len() != 32 || host_challenge.len() != CHALLENGE_LENGTH {
            return Err(DeviceError::WrongLength);
        }
        let mut context = [0; CHALLENGE_LENGTH * 2];
        context[..CHALLENGE_LENGTH].copy_from_slice(host_challenge);
        context[CHALLENGE_LENGTH..].copy_from_slice(&card_challenge);
        let s_enc = derive_key(&static_keys[..16], 0x04, &context)?;
        let s_mac = derive_key(&static_keys[16..], 0x06, &context)?;
        let s_rmac = derive_key(&static_keys[16..], 0x07, &context)?;
        let card_cryptogram = derive_cryptogram(&s_mac, 0x00, &context)?;
        let host_cryptogram = derive_cryptogram(&s_mac, 0x01, &context)?;
        Ok((
            Self::new(sid, s_enc, s_mac, s_rmac, [0; BLOCK_SIZE], [0; BLOCK_SIZE]),
            card_cryptogram,
            host_cryptogram,
        ))
    }

    pub(crate) fn begin_asymmetric(
        sid: u8,
        device_static: &SoftwareSigningKey,
        host_static_public: &[u8],
        host_ephemeral_public: &[u8],
    ) -> Result<(Self, [u8; P256_PUBLIC_KEY_LENGTH], [u8; BLOCK_SIZE])> {
        if device_static.key_kind() != KeyKind::Ec(EcCurve::P256) {
            return Err(DeviceError::InvalidData);
        }
        let normalized_host_static = match host_static_public.len() {
            64 => [vec![0x04], host_static_public.to_vec()].concat(),
            65 => host_static_public.to_vec(),
            _ => return Err(DeviceError::WrongLength),
        };
        let device_ephemeral = random_secret_key()?;
        let SoftwarePublicKey::Ec {
            uncompressed: encoded_ephemeral,
            ..
        } = device_ephemeral.public_key()
        else {
            return Err(DeviceError::SessionFailed);
        };
        let device_ephemeral_public: [u8; P256_PUBLIC_KEY_LENGTH] = encoded_ephemeral
            .as_slice()
            .try_into()
            .map_err(|_| DeviceError::SessionFailed)?;

        let ephemeral = derive_with_signing_key(&device_ephemeral, host_ephemeral_public)
            .map_err(|_| DeviceError::InvalidData)?;
        let static_secret = derive_with_signing_key(device_static, &normalized_host_static)
            .map_err(|_| DeviceError::InvalidData)?;
        let session_keys = x963_session_keys(&ephemeral, &static_secret)?;
        let mut receipt_input = Vec::with_capacity(P256_PUBLIC_KEY_LENGTH * 2);
        receipt_input.extend_from_slice(&device_ephemeral_public);
        receipt_input.extend_from_slice(host_ephemeral_public);
        let receipt = cmac(&session_keys[..16], &receipt_input)?;
        let mut counter = [0; BLOCK_SIZE];
        increment_counter(&mut counter);
        Ok((
            Self::new(
                sid,
                session_keys[16..32].try_into().unwrap(),
                session_keys[32..48].try_into().unwrap(),
                session_keys[48..64].try_into().unwrap(),
                counter,
                receipt,
            ),
            device_ephemeral_public,
            receipt,
        ))
    }

    pub(crate) fn authenticate_symmetric(
        &mut self,
        request: &Frame,
        expected_host_cryptogram: &[u8; MAC_LENGTH],
    ) -> Result<()> {
        let payload = self.verify_request_mac(request)?;
        let valid = payload.len() == 1 + MAC_LENGTH
            && payload[0] == self.sid
            && bool::from(payload[1..].ct_eq(expected_host_cryptogram));
        if !valid {
            return Err(DeviceError::AuthenticationFailed);
        }
        increment_counter(&mut self.counter);
        Ok(())
    }

    /// Decrypt one authenticated SESSION MESSAGE and return the clear request.
    pub(crate) fn decrypt_request(&mut self, request: &Frame) -> Result<Frame> {
        let payload = self.verify_request_mac(request)?;
        if payload.len() < 1 + BLOCK_SIZE
            || payload[0] != self.sid
            || (payload.len() - 1) % BLOCK_SIZE != 0
        {
            return Err(DeviceError::SessionFailed);
        }
        let iv = encrypt_block(&self.s_enc[..], &self.counter)?;
        let clear = cbc_decrypt(&self.s_enc[..], &iv, &payload[1..])?;
        Frame::parse(&unpad(clear)?)
    }

    /// Encrypt and authenticate the response using the same message counter.
    pub(crate) fn encrypt_response(&mut self, response: &Frame) -> Result<Frame> {
        let iv = encrypt_block(&self.s_enc[..], &self.counter)?;
        let ciphertext = cbc_encrypt(&self.s_enc[..], &iv, &pad(&response.encode()))?;
        let mut data = Vec::with_capacity(1 + ciphertext.len() + MAC_LENGTH);
        data.push(self.sid);
        data.extend_from_slice(&ciphertext);

        let mut encoded_without_mac = Vec::with_capacity(3 + data.len());
        encoded_without_mac
            .push(crate::CommandCode::SessionMessage as u8 | crate::frame::RESPONSE_BIT);
        encoded_without_mac.extend_from_slice(&((data.len() + MAC_LENGTH) as u16).to_be_bytes());
        encoded_without_mac.extend_from_slice(&data);
        let mut mac_input = Vec::with_capacity(BLOCK_SIZE + encoded_without_mac.len());
        mac_input.extend_from_slice(&self.mac_chaining_value);
        mac_input.extend_from_slice(&encoded_without_mac);
        let response_mac = cmac(&self.s_rmac[..], &mac_input)?;
        data.extend_from_slice(&response_mac[..MAC_LENGTH]);
        increment_counter(&mut self.counter);
        Frame::new(
            crate::CommandCode::SessionMessage as u8 | crate::frame::RESPONSE_BIT,
            data,
        )
    }

    fn verify_request_mac(&mut self, request: &Frame) -> Result<Vec<u8>> {
        if request.data.len() < MAC_LENGTH {
            return Err(DeviceError::AuthenticationFailed);
        }
        let payload_length = request.data.len() - MAC_LENGTH;
        let encoded = request.encode();
        let mut input = Vec::with_capacity(BLOCK_SIZE + 3 + payload_length);
        input.extend_from_slice(&self.mac_chaining_value);
        input.extend_from_slice(&encoded[..3 + payload_length]);
        let command_mac = cmac(&self.s_mac[..], &input)?;
        if !bool::from(command_mac[..MAC_LENGTH].ct_eq(&request.data[payload_length..])) {
            return Err(DeviceError::AuthenticationFailed);
        }
        self.mac_chaining_value = command_mac;
        Ok(request.data[..payload_length].to_vec())
    }

    fn new(
        sid: u8,
        s_enc: [u8; BLOCK_SIZE],
        s_mac: [u8; BLOCK_SIZE],
        s_rmac: [u8; BLOCK_SIZE],
        counter: [u8; BLOCK_SIZE],
        mac_chaining_value: [u8; BLOCK_SIZE],
    ) -> Self {
        Self {
            sid,
            s_enc: Zeroizing::new(s_enc),
            s_mac: Zeroizing::new(s_mac),
            s_rmac: Zeroizing::new(s_rmac),
            counter,
            mac_chaining_value,
        }
    }
}

pub(crate) fn random_secret_key() -> Result<SoftwareSigningKey> {
    SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256))
        .map_err(|_| DeviceError::StorageFailed)
}

fn derive_key(key: &[u8], constant: u8, context: &[u8]) -> Result<[u8; BLOCK_SIZE]> {
    scp03_key(key, constant, context).map_err(|_| DeviceError::SessionFailed)
}

fn derive_cryptogram(key: &[u8], constant: u8, context: &[u8]) -> Result<[u8; MAC_LENGTH]> {
    scp03_cryptogram(key, constant, context).map_err(|_| DeviceError::SessionFailed)
}

fn x963_session_keys(ephemeral: &[u8], static_secret: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    let mut shared_secret =
        Zeroizing::new(Vec::with_capacity(ephemeral.len() + static_secret.len()));
    shared_secret.extend_from_slice(ephemeral);
    shared_secret.extend_from_slice(static_secret);
    x963_kdf_sha256(&shared_secret, &SCP11_SHARED_INFO, 64)
        .map_err(|_| DeviceError::SessionFailed)?
        .as_slice()
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| DeviceError::SessionFailed)
}

fn increment_counter(counter: &mut [u8; BLOCK_SIZE]) {
    for byte in counter.iter_mut().rev() {
        let (value, overflow) = byte.overflowing_add(1);
        *byte = value;
        if !overflow {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_response_limit_accounts_for_frame_padding_session_id_and_mac() {
        assert!(secure_response_data_fits(3_116));
        assert!(!secure_response_data_fits(3_117));
        assert!(!secure_response_data_fits(usize::MAX));
    }
}
