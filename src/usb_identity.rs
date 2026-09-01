//! Worker-owned USB identity for the YubiHSM 2 bulk protocol.

use usb_gadget_worker::{
    MicrosoftCompatibleId, MicrosoftOs10, StringDescriptor, UsbPersonality, UsbSpeed,
};

pub(crate) const BULK_OUT: u8 = 0x01;
pub(crate) const BULK_IN: u8 = 0x81;
pub(crate) const MAX_PACKET_SIZE: u16 = 64;
const VENDOR_ID: u16 = 0x1050;
const PRODUCT_ID: u16 = 0x0030;

pub(crate) fn personality(serial: u32) -> UsbPersonality {
    let vendor = VENDOR_ID.to_le_bytes();
    let product = PRODUCT_ID.to_le_bytes();
    let release = 0x0241_u16.to_le_bytes();
    let device = vec![
        18, 1, 0x00, 0x02, 0, 0, 0, 64, vendor[0], vendor[1], product[0], product[1], release[0],
        release[1], 1, 2, 3, 1,
    ];
    UsbPersonality::new(UsbSpeed::FullSpeed, device, configuration_descriptor())
        .with_string(StringDescriptor::new(0, 0, [4, 3, 0x09, 0x04]))
        .with_string(StringDescriptor::new(
            1,
            0x0409,
            string_descriptor("Virtual USB Gadget"),
        ))
        .with_string(StringDescriptor::new(
            2,
            0x0409,
            string_descriptor("Virtual YubiHSM 2"),
        ))
        .with_string(StringDescriptor::new(
            3,
            0x0409,
            string_descriptor(&serial.to_string()),
        ))
        .with_microsoft_os_1(
            MicrosoftOs10::new(0x27)
                .with_compatible_id(MicrosoftCompatibleId::new(0, "WINUSB", "")),
        )
}

fn configuration_descriptor() -> Vec<u8> {
    let mut body = vec![9, 4, 0, 0, 2, 0xff, 0, 0, 0];
    endpoint(&mut body, BULK_OUT);
    endpoint(&mut body, BULK_IN);
    let total_length = u16::try_from(9 + body.len()).expect("USB configuration is too large");
    let mut configuration = vec![
        9,
        2,
        total_length as u8,
        (total_length >> 8) as u8,
        1,
        1,
        0,
        0x80,
        15,
    ];
    configuration.extend_from_slice(&body);
    configuration
}

fn endpoint(output: &mut Vec<u8>, address: u8) {
    output.extend_from_slice(&[
        7,
        5,
        address,
        0x02,
        MAX_PACKET_SIZE as u8,
        (MAX_PACKET_SIZE >> 8) as u8,
        0,
    ]);
}

fn string_descriptor(value: &str) -> Vec<u8> {
    let words = value.encode_utf16().collect::<Vec<_>>();
    let length = 2 + words.len() * 2;
    let mut descriptor = Vec::with_capacity(length);
    descriptor.push(u8::try_from(length).expect("USB string is too long"));
    descriptor.push(3);
    for word in words {
        descriptor.extend_from_slice(&word.to_le_bytes());
    }
    descriptor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_the_yubihsm_bulk_personality() {
        let personality = personality(87_654_321);
        assert_eq!(
            &personality.device_descriptor[8..12],
            &[0x50, 0x10, 0x30, 0x00]
        );
        assert_eq!(personality.configuration_descriptor[4], 1);
        assert_eq!(personality.configuration_descriptor.len(), 32);
        assert_eq!(personality.device_descriptor[16], 3);
        let microsoft = personality
            .microsoft_os_1
            .as_ref()
            .expect("YubiHSM personality must announce WinUSB");
        assert_eq!(microsoft.vendor_code, 0x27);
        assert_eq!(microsoft.compatible_ids.len(), 1);
        assert_eq!(microsoft.compatible_ids[0].interface, 0);
        assert_eq!(microsoft.compatible_ids[0].compatible_id, "WINUSB");
        assert_eq!(microsoft.compatible_ids[0].sub_compatible_id, "");
        assert!(personality.strings.iter().any(|descriptor| {
            descriptor.index == 3
                && descriptor.language_id == 0x0409
                && descriptor.descriptor == string_descriptor("87654321")
        }));
        for address in [BULK_OUT, BULK_IN] {
            assert!(
                personality
                    .configuration_descriptor
                    .windows(3)
                    .any(|bytes| bytes == [7, 5, address])
            );
        }
    }
}
