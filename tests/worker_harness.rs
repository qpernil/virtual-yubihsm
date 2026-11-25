//! Real worker process tests with protocol-neutral simulated endpoint handles.
#![cfg(unix)]

use std::process::Command;
use usb_gadget_harness::{Harness, Kind, Record, Resource, TestDirectory, UsbBusEvent};
use virtual_yubihsm_core::{CommandCode, DeviceError, Frame};

fn launch(directory: &TestDirectory) -> Harness {
    let mut command = Command::new(env!("CARGO_BIN_EXE_virtual-yubihsm-worker"));
    command.args(["--serial", "12345678", "--persistence", "immediate"]);
    Harness::spawn(
        &mut command,
        directory,
        &[
            Resource::Sink("display-spi"),
            Resource::Sink("display-control"),
            Resource::DigitalInput("reconnect-button"),
        ],
    )
    .unwrap()
}
fn ready(directory: &TestDirectory) -> Harness {
    let mut worker = launch(directory);
    let personality = worker.configure().unwrap();
    assert_eq!(
        &personality.device_descriptor[8..12],
        &[0x50, 0x10, 0x30, 0]
    );
    worker.activate().unwrap();
    barrier(&mut worker);
    worker
}
fn barrier(worker: &mut Harness) {
    assert_eq!(
        worker.control([0xc0, 0xff, 0, 0, 0, 0, 0, 0], &[]).unwrap(),
        [0]
    );
}
fn exchange(worker: &Harness, request: &[u8]) -> Vec<u8> {
    worker.endpoint(1).unwrap().send(request).unwrap();
    loop {
        let response = worker.endpoint(0x81).unwrap().receive().unwrap();
        if !response.is_empty() {
            return response;
        }
    }
}
fn command(worker: &Harness, command: CommandCode, payload: &[u8]) -> Frame {
    Frame::parse(&exchange(
        worker,
        &Frame::new(command as u8, payload.to_vec())
            .unwrap()
            .encode(),
    ))
    .unwrap()
}
fn session(worker: &Harness) -> u8 {
    let mut data = vec![0, 1];
    data.extend_from_slice(&[0x42; 8]);
    let response = command(worker, CommandCode::CreateSession, &data);
    assert_eq!(response.command, CommandCode::CreateSession as u8 | 0x80);
    assert_eq!(response.data.len(), 17);
    response.data[0]
}

#[test]
fn real_bulk_worker_handles_frames_zlps_and_malformed_transfers() {
    let directory = TestDirectory::new().unwrap();
    let worker = ready(&directory);
    for length in [0, 1, 60, 61, 62, 125, 1024, 2048] {
        let data: Vec<_> = (0..length).map(|index| index as u8).collect();
        let response = command(&worker, CommandCode::Echo, &data);
        assert_eq!(response.command, 0x81);
        assert_eq!(response.data, data);
        if (length + 3) % 64 == 0 {
            assert!(worker.endpoint(0x81).unwrap().receive().unwrap().is_empty());
        }
    }
    worker.endpoint(1).unwrap().send(&[]).unwrap(); // OUT ZLP is not a command.
    let info = command(&worker, CommandCode::GetDeviceInfo, &[]);
    assert_eq!(info.command, 0x86);
    assert!(info.data.len() >= 9);
    let malformed = exchange(&worker, &[1, 0, 10, 0]);
    let error = Frame::parse(&malformed).unwrap();
    assert_eq!(error.command, 0x7f);
    assert_eq!(error.data, [DeviceError::WrongLength as u8]);
    assert_eq!(
        command(&worker, CommandCode::Echo, b"after malformed input").data,
        b"after malformed input"
    );
    worker.shutdown().unwrap();
}

#[test]
fn suspend_preserves_sessions_disable_and_unbind_clear_them() {
    let directory = TestDirectory::new().unwrap();
    let mut worker = ready(&directory);
    assert_eq!(session(&worker), 0);
    worker.bus_event(UsbBusEvent::Suspend).unwrap();
    worker.bus_event(UsbBusEvent::Resume).unwrap();
    barrier(&mut worker);
    assert_eq!(session(&worker), 1);
    worker.bus_event(UsbBusEvent::Disable).unwrap();
    barrier(&mut worker);
    worker.bus_event(UsbBusEvent::Enable).unwrap();
    barrier(&mut worker);
    assert_eq!(session(&worker), 0);
    worker.bus_event(UsbBusEvent::Unbind).unwrap();
    worker.bus_event(UsbBusEvent::Bind).unwrap();
    worker.bus_event(UsbBusEvent::Enable).unwrap();
    barrier(&mut worker);
    assert_eq!(session(&worker), 0);
    worker.shutdown().unwrap();
}

#[test]
fn real_reconnect_input_quiesces_and_reinserts_then_restarts_from_state() {
    let directory = TestDirectory::new().unwrap();
    let mut worker = ready(&directory);
    let before = command(&worker, CommandCode::GetDevicePublicKey, &[]);
    assert_ne!(before.command, 0x7f);
    worker.set_input("reconnect-button", true).unwrap();
    let absent = worker.receive().unwrap();
    assert_eq!(absent.kind, Kind::Configure);
    assert!(absent.body.is_empty());
    worker.quiesce(absent.request_id).unwrap();
    worker.set_input("reconnect-button", false).unwrap();
    worker.configure().unwrap();
    assert_eq!(worker.generation(), 2);
    worker.activate().unwrap();
    barrier(&mut worker);
    assert_eq!(
        command(&worker, CommandCode::GetDevicePublicKey, &[]).data,
        before.data
    );
    worker.shutdown().unwrap();
    let worker = ready(&directory);
    assert_eq!(
        command(&worker, CommandCode::GetDevicePublicKey, &[]).data,
        before.data
    );
    worker.shutdown().unwrap();
}

#[test]
fn configuration_rejection_and_stale_generation_fail_closed() {
    let directory = TestDirectory::new().unwrap();
    let mut worker = launch(&directory);
    let configuration = worker.receive().unwrap();
    assert_eq!(configuration.kind, Kind::Configure);
    worker
        .send(
            &Record::new(
                Kind::ConfigurationRejected,
                0,
                configuration.request_id,
                b"test rejection".to_vec(),
            ),
            &[],
        )
        .unwrap();
    assert!(!worker.wait_for_exit().unwrap().success());
    assert!(worker.logs().contains("test rejection"));
    drop(worker);
    let mut worker = ready(&directory);
    worker
        .send(
            &Record::new(
                Kind::UsbBusEvent,
                999,
                0,
                UsbBusEvent::Enable.encode(2).to_vec(),
            ),
            &[],
        )
        .unwrap();
    worker.retire_endpoints().unwrap();
    assert!(!worker.wait_for_exit().unwrap().success());
    assert!(worker.logs().contains("mismatched runtime record"));
}
