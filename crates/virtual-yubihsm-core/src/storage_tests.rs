use super::*;

fn opaque(id: u16, size: usize) -> ObjectRecord {
    ObjectRecord {
        info: ObjectInfo {
            capabilities: CapabilitySet::NONE,
            id,
            length: size as u16,
            domains: 1,
            object_type: ObjectType::Opaque,
            algorithm: OPAQUE_DATA_ALGORITHM,
            sequence: 0,
            origin: 2,
            label: b"capacity".to_vec(),
            delegated_capabilities: CapabilitySet::NONE,
        },
        material: ObjectMaterial::Opaque(vec![0x5a; size]),
    }
}

fn storage(device: &mut Device) -> [u16; 5] {
    let response = device.execute_inner(
        device.session_authorization(1).unwrap(),
        &Frame::new(CommandCode::GetStorageInfo as u8, []).unwrap(),
    );
    assert_eq!(response.command, CommandCode::GetStorageInfo as u8 | 0x80);
    std::array::from_fn(|i| u16::from_be_bytes(response.data[2 * i..2 * i + 2].try_into().unwrap()))
}

fn put(device: &mut Device, id: u16, size: usize) -> Frame {
    let mut data = id.to_be_bytes().to_vec();
    let mut label = [0; 40];
    label[..8].copy_from_slice(b"capacity");
    data.extend_from_slice(&label);
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&CapabilitySet::from_capabilities([Capability::PutOpaque]).to_bytes());
    data.push(OPAQUE_DATA_ALGORITHM);
    data.extend(std::iter::repeat_n(0x5a, size));
    device.execute_inner(
        device.session_authorization(1).unwrap(),
        &Frame::new(CommandCode::PutOpaque as u8, data).unwrap(),
    )
}

fn delete(device: &mut Device, id: u16) {
    let mut data = id.to_be_bytes().to_vec();
    data.push(ObjectType::Opaque as u8);
    let response = device.execute_inner(
        device.session_authorization(1).unwrap(),
        &Frame::new(CommandCode::DeleteObject as u8, data).unwrap(),
    );
    assert_eq!(response.command, CommandCode::DeleteObject as u8 | 0x80);
}

#[test]
fn storage_page_boundaries_match_physical_opaque_measurements() {
    let mut device = Device::factory_default(DeviceConfig::default());
    let baseline = [256, 255, 1024, 1023, 126];
    assert_eq!(storage(&mut device), baseline);
    for (size, pages) in [
        (1, 1),
        (125, 1),
        (126, 1),
        (127, 2),
        (166, 2),
        (206, 2),
        (251, 2),
        (252, 2),
        (253, 3),
    ] {
        assert_eq!(
            put(&mut device, 2, size).command,
            CommandCode::PutOpaque as u8 | 0x80
        );
        assert_eq!(storage(&mut device), [256, 254, 1024, 1023 - pages, 126]);
        delete(&mut device, 2);
        assert_eq!(storage(&mut device), baseline);
    }
}

#[test]
fn storage_object_limit_rejects_without_mutation_and_delete_recovers_capacity() {
    let mut device = Device::factory_default(DeviceConfig::default());
    for id in 1..256 {
        assert_eq!(put(&mut device, id, 1).command, 0xc2);
    }
    assert_eq!(storage(&mut device), [256, 0, 1024, 768, 126]);
    let before = device.persistent_state().unwrap();
    assert_eq!(
        put(&mut device, 256, 1).data,
        [DeviceError::StorageFailed as u8]
    );
    assert_eq!(device.persistent_state().unwrap(), before);
    // Updating an existing record does not consume another object slot.
    assert_eq!(put(&mut device, 1, 127).command, 0xc2);
    assert_eq!(storage(&mut device), [256, 0, 1024, 767, 126]);
    delete(&mut device, 1);
    assert_eq!(put(&mut device, 256, 1).command, 0xc2);
    assert_eq!(storage(&mut device), [256, 0, 1024, 768, 126]);
}

#[test]
fn storage_page_limit_rejects_growth_atomically_and_shrink_recovers_capacity() {
    let mut device = Device::factory_default(DeviceConfig::default());
    for id in 1..=15 {
        assert_eq!(put(&mut device, id, 64 * 126).command, 0xc2);
    }
    assert_eq!(put(&mut device, 16, 63 * 126).command, 0xc2);
    assert_eq!(storage(&mut device), [256, 239, 1024, 0, 126]);
    let before = device.persistent_state().unwrap();
    assert_eq!(
        put(&mut device, 17, 1).data,
        [DeviceError::StorageFailed as u8]
    );
    assert_eq!(
        put(&mut device, 16, 64 * 126).data,
        [DeviceError::StorageFailed as u8]
    );
    assert_eq!(device.persistent_state().unwrap(), before);
    assert_eq!(put(&mut device, 16, 62 * 126).command, 0xc2);
    assert_eq!(storage(&mut device)[3], 1);
    assert_eq!(put(&mut device, 17, 1).command, 0xc2);
    assert_eq!(storage(&mut device)[3], 0);
    delete(&mut device, 1);
    assert_eq!(storage(&mut device)[3], 64);
    assert_eq!(put(&mut device, 18, 64 * 126).command, 0xc2);
}

#[test]
fn storage_limits_apply_to_provisioning_and_restoration_with_explicit_unlimited_opt_out() {
    let mut device = Device::factory_default(DeviceConfig {
        unlimited_storage: true,
        ..DeviceConfig::default()
    });
    for id in 1..=257 {
        device.provision_object(opaque(id, 1024)).unwrap();
    }
    let state = device.persistent_state().unwrap();
    assert!(matches!(
        Device::from_persistent_state(DeviceConfig::default(), &state),
        Err(DeviceError::StorageFailed)
    ));
    let mut restored = Device::from_persistent_state(
        DeviceConfig {
            unlimited_storage: true,
            ..DeviceConfig::default()
        },
        &state,
    )
    .unwrap();
    assert_eq!(restored.objects.len(), 258);
    assert_eq!(storage(&mut restored)[0], u16::MAX);
    let mut bounded = Device::factory_default(DeviceConfig::default());
    for id in 1..256 {
        bounded.provision_object(opaque(id, 1)).unwrap();
    }
    let before = bounded.persistent_state().unwrap();
    assert_eq!(
        bounded.provision_object(opaque(256, 1)),
        Err(DeviceError::StorageFailed)
    );
    assert_eq!(bounded.persistent_state().unwrap(), before);
}

#[test]
fn storage_page_costs_reproduce_published_rsa_key_capacities() {
    for (length, capacity) in [(896usize, 127), (1344, 93), (1792, 68)] {
        assert_eq!(
            (STORAGE_PAGES - 1) / length.div_ceil(STORAGE_PAGE_SIZE),
            capacity
        );
    }
}
