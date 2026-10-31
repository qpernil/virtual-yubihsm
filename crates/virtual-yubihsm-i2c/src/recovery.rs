//! I2C-frontend control operation, outside the HSM command executor.
const PREFIX: &[u8] = b"\x00\x00\x0dBSCRECOV\x01";

pub(super) fn response(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() != PREFIX.len() + 4 || !request.starts_with(PREFIX) {
        return None;
    }
    let mut response = request.to_vec();
    response[0] = 0x80;
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_versioned_control_requests_bypass_the_hsm() {
        let mut request = PREFIX.to_vec();
        request.extend_from_slice(&0x12345678_u32.to_be_bytes());
        let reply = response(&request).unwrap();
        assert_eq!(reply[0], 0x80);
        assert_eq!(&reply[1..], &request[1..]);
        assert!(response(&request[..request.len() - 1]).is_none());
        request.push(0);
        assert!(response(&request).is_none());
        request.pop();
        request[11] = 2;
        assert!(response(&request).is_none());
        request[11] = 1;
        request[0] = 1; // Ordinary Echo, even with the same payload, stays an HSM command.
        assert!(response(&request).is_none());
        assert!(response(b"hello").is_none());
    }
}
