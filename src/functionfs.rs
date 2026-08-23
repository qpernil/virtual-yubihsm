//! Supervisor-facing FunctionFS runtime for the YubiHSM bulk endpoints.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::{
    usb_identity::{BULK_IN, BULK_OUT, MAX_PACKET_SIZE},
    worker_protocol::{validate_initial_resources, Channel, Kind, Record, STATE_DIRECTORY_ENV},
};
use std::{
    env, fs,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use virtual_yubihsm_core::{Device, DeviceConfig};

const MAX_TRANSFER: usize = u16::MAX as usize + 3;
const ENDPOINT_RETRY_DELAY: Duration = Duration::from_millis(10);

pub(crate) fn run_worker(serial: u32, stop: &'static AtomicBool) -> io::Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to run the protocol worker as root",
        ));
    }
    let control = Channel::from_fixed_descriptor();
    let resources = validate_initial_resources(control.receive()?)?;
    if !resources.is_empty() {
        return invalid("virtual-yubihsm does not accept named local resources");
    }
    let state_directory = required_path(STATE_DIRECTORY_ENV)?;
    let state_path = state_directory.join(format!("yubihsm-{serial}.cbor"));
    let config = DeviceConfig {
        serial,
        ..DeviceConfig::default()
    };
    let device = Arc::new(Mutex::new(load_or_create_state(config, &state_path)?));
    let personality = crate::usb_identity::personality().to_cbor()?;
    let configure_request = 1;
    control.send(&Record::new(
        Kind::Configure,
        0,
        configure_request,
        personality,
    ))?;
    let endpoints_record = control.receive()?;
    if endpoints_record.kind == Kind::ConfigurationRejected {
        return invalid(format!(
            "supervisor rejected USB personality: {}",
            String::from_utf8_lossy(&endpoints_record.body)
        ));
    }
    if endpoints_record.kind != Kind::UsbEndpoints
        || endpoints_record.generation == 0
        || endpoints_record.request_id != configure_request
    {
        return invalid("expected USB endpoints for the published personality");
    }
    let generation = endpoints_record.generation;
    let endpoints = Endpoints::from_record(endpoints_record)?;
    stop.store(false, Ordering::Relaxed);
    let runtime = EndpointRuntime::start(endpoints, Arc::clone(&device), state_path, stop)?;
    control.send(&Record::new(
        Kind::Serving,
        generation,
        configure_request,
        Vec::new(),
    ))?;

    loop {
        let mut poll_fd = libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        // SAFETY: poll_fd points to one initialized pollfd.
        let ready = unsafe { libc::poll(&mut poll_fd, 1, 250) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if stop.load(Ordering::Relaxed) {
            return runtime
                .shutdown()
                .and_then(|()| Err(io::Error::other("YubiHSM endpoint worker stopped")));
        }
        if ready == 0 {
            continue;
        }
        if poll_fd.revents & libc::POLLIN == 0 {
            if poll_fd.revents & libc::POLLHUP != 0 {
                stop.store(true, Ordering::Relaxed);
                return Ok(());
            }
            return Err(io::Error::other(format!(
                "worker-control descriptor reported poll events 0x{:x}",
                poll_fd.revents
            )));
        }
        let record = match control.receive() {
            Ok(record) => record,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                stop.store(true, Ordering::Relaxed);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if record.generation != generation || !record.files.is_empty() {
            return invalid("supervisor sent a mismatched runtime record");
        }
        match record.kind {
            Kind::UsbBusEvent if record.request_id == 0 => {
                let event = parse_bus_event(&record.body)?;
                if matches!(event, 0 | 1 | 3) {
                    device
                        .lock()
                        .map_err(|_| io::Error::other("device lock poisoned"))?
                        .clear_sessions();
                }
            }
            Kind::UsbControlRequest if record.request_id != 0 => {
                control.send(&Record::new(
                    Kind::UsbControlResponse,
                    generation,
                    record.request_id,
                    vec![0],
                ))?;
            }
            Kind::Quiesce if record.body.is_empty() => {
                stop.store(true, Ordering::Relaxed);
                runtime.shutdown()?;
                control.send(&Record::new(
                    Kind::Quiesced,
                    generation,
                    record.request_id,
                    Vec::new(),
                ))?;
                return Ok(());
            }
            _ => return invalid(format!("unexpected runtime record {:?}", record.kind)),
        }
    }
}

struct Endpoints {
    output: File,
    input: File,
}

impl Endpoints {
    fn from_record(record: Record) -> io::Result<Self> {
        let count = record
            .body
            .get(..2)
            .ok_or_else(|| data_error("truncated USB endpoint map"))?;
        let count = u16::from_be_bytes(count.try_into().unwrap()) as usize;
        if record.body.len() != 2 + count * 4 || record.files.len() != count {
            return invalid("USB endpoint map and descriptors differ");
        }
        let mut output = None;
        let mut input = None;
        for (entry, file) in record.body[2..].chunks_exact(4).zip(record.files) {
            let address = entry[0];
            let transfer_type = entry[1];
            let packet_size = u16::from_be_bytes(entry[2..4].try_into().unwrap());
            if transfer_type != 2 || packet_size != MAX_PACKET_SIZE {
                return invalid("YubiHSM endpoints must be full-speed bulk endpoints");
            }
            let target = match address {
                BULK_OUT => &mut output,
                BULK_IN => &mut input,
                _ => return invalid(format!("unexpected USB endpoint {address:#04x}")),
            };
            if target.replace(file).is_some() {
                return invalid(format!("duplicate USB endpoint {address:#04x}"));
            }
        }
        Ok(Self {
            output: output.ok_or_else(|| data_error("missing YubiHSM OUT endpoint"))?,
            input: input.ok_or_else(|| data_error("missing YubiHSM IN endpoint"))?,
        })
    }
}

struct EndpointRuntime {
    thread: thread::JoinHandle<io::Result<()>>,
}

impl EndpointRuntime {
    fn start(
        endpoints: Endpoints,
        device: Arc<Mutex<Device>>,
        state_path: PathBuf,
        stop: &'static AtomicBool,
    ) -> io::Result<Self> {
        let thread = thread::Builder::new()
            .name("yubihsm-usb".to_owned())
            .spawn(move || serve_endpoint(endpoints, device, &state_path, stop))?;
        Ok(Self { thread })
    }

    fn shutdown(self) -> io::Result<()> {
        self.thread
            .join()
            .map_err(|_| io::Error::other("YubiHSM endpoint thread panicked"))?
    }
}

fn serve_endpoint(
    mut endpoints: Endpoints,
    device: Arc<Mutex<Device>>,
    state_path: &Path,
    stop: &'static AtomicBool,
) -> io::Result<()> {
    let result = (|| {
        let mut request = vec![0_u8; MAX_TRANSFER];
        while !stop.load(Ordering::Relaxed) {
            match endpoints.output.read(&mut request) {
                Ok(0) => {}
                Ok(length) => {
                    let response = {
                        let mut device = device
                            .lock()
                            .map_err(|_| io::Error::other("device lock poisoned"))?;
                        let response = device.handle_encoded(&request[..length]);
                        if device.take_persistent_change() {
                            persist_device_state(&device, state_path)?;
                        }
                        response
                    };
                    write_transfer(&mut endpoints.input, &response)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if endpoint_is_gone(&error) => thread::sleep(ENDPOINT_RETRY_DELAY),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    })();
    if result.is_err() {
        stop.store(true, Ordering::Relaxed);
    }
    result
}

fn load_or_create_state(config: DeviceConfig, path: &Path) -> io::Result<Device> {
    match fs::read(path) {
        Ok(encoded) => Device::from_persistent_state(config, &encoded).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("load persistent YubiHSM state {}: {error}", path.display()),
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let device = Device::factory_default(config);
            persist_device_state(&device, path)?;
            Ok(device)
        }
        Err(error) => Err(with_context(error, "read persistent YubiHSM state")),
    }
}

fn persist_device_state(device: &Device, path: &Path) -> io::Result<()> {
    let encoded = device
        .persistent_state()
        .map_err(|error| io::Error::other(format!("encode persistent YubiHSM state: {error}")))?;
    persist_state(&encoded, path)
}

fn persist_state(encoded: &[u8], path: &Path) -> io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| with_context(error, "create temporary YubiHSM state"))?;
        file.write_all(encoded)
            .map_err(|error| with_context(error, "write temporary YubiHSM state"))?;
        file.sync_all()
            .map_err(|error| with_context(error, "sync temporary YubiHSM state"))?;
        drop(file);
        fs::rename(&temporary, path)
            .map_err(|error| with_context(error, "replace persistent YubiHSM state"))?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("persistent state has no parent directory"))?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_transfer(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    loop {
        match file.write(bytes) {
            Ok(length) if length == bytes.len() => return Ok(()),
            Ok(length) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("FunctionFS accepted {length} of {} bytes", bytes.len()),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if endpoint_is_gone(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn endpoint_is_gone(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(19 | 32 | 108))
}

fn parse_bus_event(body: &[u8]) -> io::Result<u8> {
    if body.len() != usb_gadget_worker::USB_BUS_EVENT_BODY_LENGTH || body[0] > 6 || body[0] == 4 {
        return invalid("invalid USB bus event");
    }
    Ok(body[0])
}

fn required_path(name: &str) -> io::Result<PathBuf> {
    let path = env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} is not set")))?;
    if !path.is_absolute() {
        return invalid(format!("{name} must be an absolute path"));
    }
    Ok(path)
}

fn invalid<T>(message: impl Into<String>) -> io::Result<T> {
    Err(data_error(message))
}

fn data_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn with_context(error: io::Error, context: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_state_directories() {
        let name = "VIRTUAL_YUBIHSM_TEST_STATE_DIRECTORY";
        env::set_var(name, "relative");
        assert_eq!(
            required_path(name).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        env::remove_var(name);
    }

    #[test]
    fn validates_bus_event_shape() {
        assert_eq!(parse_bus_event(&[2, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap(), 2);
        assert!(parse_bus_event(&[4, 0, 0, 0, 0, 0, 0, 0, 1]).is_err());
    }
}
