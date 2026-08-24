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
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};
use usb_gadget_worker::{EndpointLifecycle, UsbBusEvent};
use virtual_yubihsm_core::{
    CommandCode, Device, DeviceConfig, DeviceError, Frame, SessionAuthorization,
};

const MAX_TRANSFER: usize = u16::MAX as usize + 3;
fn publish_personality(
    control: &Channel<'static>,
    generation: u32,
    request_id: u32,
    personality: &[u8],
    display: &crate::display::Controller,
) -> io::Result<()> {
    control.send(&Record::new(
        Kind::Configure,
        generation,
        request_id,
        personality.to_vec(),
    ))?;
    if personality.is_empty() {
        display.personality_absent()
    } else {
        display.personality_present()
    }
}

pub(crate) fn run_worker(
    serial: u32,
    display_kind: crate::DisplayKind,
    stop: &'static AtomicBool,
) -> io::Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to run the protocol worker as root",
        ));
    }
    let control = Channel::from_fixed_descriptor();
    let resources = InitialResources::parse(validate_initial_resources(control.receive()?)?)?;
    let state_directory = required_path(STATE_DIRECTORY_ENV)?;
    let state_path = state_directory.join(format!("yubihsm-{serial}.cbor"));
    let config = DeviceConfig {
        serial,
        ..DeviceConfig::default()
    };
    let device = Arc::new(Mutex::new(load_or_create_state(config, &state_path)?));
    let personality = crate::usb_identity::personality(serial).to_cbor()?;
    let display = crate::display::Controller::start(
        resources.display_spi,
        resources.display_control,
        display_kind,
    )?;
    let buttons = match crate::buttons::Controller::start(resources.reconnect_button) {
        Ok(buttons) => buttons,
        Err(error) => {
            let _ = display.shutdown();
            return Err(error);
        }
    };
    let mut configure_request = 1;
    let result = (|| {
        if buttons.reconnect_pressed() {
            eprintln!("virtual-yubihsm-worker: USB absent at startup while KEY3 is held");
            publish_personality(&control, 0, configure_request, &[], &display)?;
            if !wait_for_reinsert(
                &control,
                0,
                &buttons,
                &display,
                &personality,
                &mut configure_request,
                stop,
            )? {
                return Ok(());
            }
        } else {
            publish_personality(&control, 0, configure_request, &personality, &display)?;
        }
        loop {
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
            let lifecycle = Arc::new(EndpointLifecycle::new());
            let runtime = EndpointRuntime::start(
                endpoints,
                Arc::clone(&device),
                state_path.clone(),
                stop,
                display.activity(),
                Arc::clone(&lifecycle),
            )?;
            control.send(&Record::new(
                Kind::Serving,
                generation,
                configure_request,
                Vec::new(),
            ))?;

            let control_result = serve_control(
                &control,
                generation,
                &mut configure_request,
                ControlServices {
                    device: &device,
                    display: &display,
                    buttons: &buttons,
                    stop,
                    lifecycle: &lifecycle,
                },
            );
            stop.store(true, Ordering::Relaxed);
            lifecycle.stop();
            let runtime_result = runtime.shutdown();
            let outcome = control_result?;
            runtime_result?;
            match outcome {
                ControlOutcome::Quiesce {
                    request_id,
                    ejected,
                } => {
                    control.send(&Record::new(
                        Kind::Quiesced,
                        generation,
                        request_id,
                        Vec::new(),
                    ))?;
                    if !ejected {
                        return Ok(());
                    }
                    stop.store(false, Ordering::Relaxed);
                    if !wait_for_reinsert(
                        &control,
                        generation,
                        &buttons,
                        &display,
                        &personality,
                        &mut configure_request,
                        stop,
                    )? {
                        return Ok(());
                    }
                }
                ControlOutcome::Exit => return Ok(()),
            }
        }
    })();
    stop.store(true, Ordering::Relaxed);
    let button_result = buttons.shutdown();
    let display_result = display.shutdown();
    result.and(button_result).and(display_result)
}

struct InitialResources {
    display_spi: File,
    display_control: File,
    reconnect_button: File,
}

impl InitialResources {
    fn parse(resources: Vec<(String, File)>) -> io::Result<Self> {
        let mut display_spi = None;
        let mut display_control = None;
        let mut reconnect_button = None;
        for (name, file) in resources {
            let target = match name.as_str() {
                "display-spi" => &mut display_spi,
                "display-control" => &mut display_control,
                "reconnect-button" => &mut reconnect_button,
                _ => return invalid(format!("unexpected initial resource {name}")),
            };
            if target.replace(file).is_some() {
                return invalid(format!("duplicate initial resource {name}"));
            }
        }
        Ok(Self {
            display_spi: display_spi.ok_or_else(|| data_error("missing display-spi resource"))?,
            display_control: display_control
                .ok_or_else(|| data_error("missing display-control resource"))?,
            reconnect_button: reconnect_button
                .ok_or_else(|| data_error("missing reconnect-button resource"))?,
        })
    }
}

enum ControlOutcome {
    Quiesce { request_id: u32, ejected: bool },
    Exit,
}

struct ControlServices<'a> {
    device: &'a Arc<Mutex<Device>>,
    display: &'a crate::display::Controller,
    buttons: &'a crate::buttons::Controller,
    stop: &'static AtomicBool,
    lifecycle: &'a EndpointLifecycle,
}

fn serve_control(
    control: &Channel<'static>,
    generation: u32,
    configure_request: &mut u32,
    services: ControlServices<'_>,
) -> io::Result<ControlOutcome> {
    let ControlServices {
        device,
        display,
        buttons,
        stop,
        lifecycle,
    } = services;
    let mut unconfiguration_pending = false;
    loop {
        let mut poll_fds = [
            libc::pollfd {
                fd: control.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: buttons.reconnect_descriptor(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: poll_fds contains valid descriptors for the duration of poll.
        let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, 250) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if stop.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "YubiHSM endpoint generation stopped",
            ));
        }
        if ready == 0 {
            continue;
        }

        if poll_fds[0].revents & libc::POLLIN != 0 {
            let record = match control.receive() {
                Ok(record) => record,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(ControlOutcome::Exit);
                }
                Err(error) => return Err(error),
            };
            if record.generation != generation || !record.files.is_empty() {
                return invalid("supervisor sent a mismatched runtime record");
            }
            match record.kind {
                Kind::UsbBusEvent if record.request_id == 0 => {
                    let (event, activation) = UsbBusEvent::decode(&record.body)?;
                    eprintln!(
                        "virtual-yubihsm-worker: USB bus event {event:?} generation={generation} activation={activation}"
                    );
                    if event == UsbBusEvent::Enable {
                        lifecycle.activate(activation);
                    }
                    if matches!(
                        event,
                        UsbBusEvent::Bind | UsbBusEvent::Unbind | UsbBusEvent::Disable
                    ) {
                        device
                            .lock()
                            .map_err(|_| io::Error::other("device lock poisoned"))?
                            .clear_sessions();
                    }
                    match event {
                        UsbBusEvent::Bind => display.bind()?,
                        UsbBusEvent::Unbind => display.unbind()?,
                        UsbBusEvent::Suspend => display.suspend()?,
                        UsbBusEvent::Resume => display.resume()?,
                        _ => {}
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
                    eprintln!(
                        "virtual-yubihsm-worker: quiescing generation={generation} request={}",
                        record.request_id
                    );
                    lifecycle.stop();
                    display.unbind()?;
                    return if record.request_id == 0 {
                        Ok(ControlOutcome::Quiesce {
                            request_id: 0,
                            ejected: false,
                        })
                    } else if unconfiguration_pending && record.request_id == *configure_request {
                        Ok(ControlOutcome::Quiesce {
                            request_id: record.request_id,
                            ejected: true,
                        })
                    } else {
                        invalid("supervisor quiesced an unknown configuration request")
                    };
                }
                _ => return invalid(format!("unexpected runtime record {:?}", record.kind)),
            }
        } else if poll_fds[0].revents != 0 {
            return if poll_fds[0].revents & libc::POLLHUP != 0 {
                Ok(ControlOutcome::Exit)
            } else {
                Err(io::Error::other(format!(
                    "worker-control descriptor reported poll events 0x{:x}",
                    poll_fds[0].revents
                )))
            };
        }

        if poll_fds[1].revents & libc::POLLIN != 0
            && !unconfiguration_pending
            && buttons.take_reconnect_state()?
        {
            let request_id = configure_request
                .checked_add(1)
                .ok_or_else(|| io::Error::other("USB configuration request overflow"))?;
            publish_personality(control, generation, request_id, &[], display)?;
            *configure_request = request_id;
            unconfiguration_pending = true;
            eprintln!(
                "virtual-yubihsm-worker: KEY3 requested USB eject generation={generation} request={request_id}"
            );
        }
        let unexpected = poll_fds[1].revents & !libc::POLLIN;
        if unexpected != 0 {
            return Err(io::Error::other(format!(
                "reconnect notification descriptor reported poll events 0x{unexpected:x}"
            )));
        }
    }
}

fn wait_for_reinsert(
    control: &Channel<'static>,
    generation: u32,
    buttons: &crate::buttons::Controller,
    display: &crate::display::Controller,
    personality: &[u8],
    configure_request: &mut u32,
    stop: &'static AtomicBool,
) -> io::Result<bool> {
    loop {
        let mut poll_fds = [
            libc::pollfd {
                fd: control.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: buttons.reconnect_descriptor(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: poll_fds contains valid descriptors for the duration of poll.
        let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, 250) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if stop.load(Ordering::Relaxed) {
            return Ok(false);
        }
        if ready == 0 {
            continue;
        }
        if poll_fds[0].revents != 0 {
            return match control.receive() {
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
                Err(error) => Err(error),
                Ok(record) => invalid(format!(
                    "unexpected supervisor message while USB is ejected: {:?}",
                    record.kind
                )),
            };
        }
        if poll_fds[1].revents & libc::POLLIN != 0 && !buttons.take_reconnect_state()? {
            let request_id = configure_request
                .checked_add(1)
                .ok_or_else(|| io::Error::other("USB configuration request overflow"))?;
            publish_personality(control, generation, request_id, personality, display)?;
            *configure_request = request_id;
            eprintln!(
                "virtual-yubihsm-worker: KEY3 requested USB insertion generation={generation} request={request_id}"
            );
            return Ok(true);
        }
        let unexpected = poll_fds[1].revents & !libc::POLLIN;
        if unexpected != 0 {
            return Err(io::Error::other(format!(
                "reconnect notification descriptor reported poll events 0x{unexpected:x}"
            )));
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
            set_nonblocking(&file)?;
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
        display_activity: crate::display::Activity,
        lifecycle: Arc<EndpointLifecycle>,
    ) -> io::Result<Self> {
        let thread = thread::Builder::new()
            .name("yubihsm-usb".to_owned())
            .spawn(move || {
                serve_endpoint(
                    endpoints,
                    device,
                    &state_path,
                    stop,
                    display_activity,
                    lifecycle,
                )
            })?;
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
    display_activity: crate::display::Activity,
    lifecycle: Arc<EndpointLifecycle>,
) -> io::Result<()> {
    let result = (|| {
        let mut request = vec![0_u8; MAX_TRANSFER];
        let mut activation = 0;
        while let Some(next_activation) = lifecycle.wait_for_activation_after(activation) {
            activation = next_activation;
            loop {
                if stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
                match endpoints.output.read(&mut request) {
                    Ok(0) => {}
                    Ok(length) => {
                        let activity = display_activity.begin();
                        let response = {
                            let mut device = device
                                .lock()
                                .map_err(|_| io::Error::other("device lock poisoned"))?;
                            let outer_request = Frame::parse(&request[..length]);
                            let session_id = outer_request.as_ref().ok().and_then(session_id);
                            let response = device.handle_encoded_observing(
                                &request[..length],
                                |authorization, request, response| {
                                    log_authenticated_failure(
                                        session_id,
                                        authorization,
                                        request,
                                        response,
                                    );
                                    if request.command == CommandCode::BlinkDevice as u8
                                        && response.command
                                            == (CommandCode::BlinkDevice as u8 | 0x80)
                                    {
                                        display_activity.identify(request.data[0]);
                                    }
                                },
                            );
                            log_outer_failure(outer_request.as_ref(), &response, length);
                            if device.take_persistent_change() {
                                persist_device_state(&device, state_path)?;
                            }
                            response
                        };
                        write_transfer(&mut endpoints.input, &response)?;
                        drop(activity);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if endpoint_is_unavailable(&error) => break,
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    })();
    if result.is_err() {
        stop.store(true, Ordering::Relaxed);
    }
    result
}

fn session_id(request: &Frame) -> Option<u8> {
    matches!(
        CommandCode::from_byte(request.command),
        Some(CommandCode::AuthenticateSession | CommandCode::SessionMessage)
    )
    .then(|| request.data.first().copied())
    .flatten()
}

fn log_authenticated_failure(
    session_id: Option<u8>,
    authorization: SessionAuthorization,
    request: &Frame,
    response: &Frame,
) {
    let Some((error_code, error)) = response_error(response) else {
        return;
    };
    eprintln!(
        "virtual-yubihsm-worker: authenticated command {} ({:#04x}) failed: {} ({:#04x}); session={} authentication-key={:#06x}",
        command_name(request.command),
        request.command,
        error,
        error_code,
        session_id.map_or_else(|| "unknown".to_owned(), |sid| sid.to_string()),
        authorization.authentication_key_id,
    );
}

fn log_outer_failure(
    request: Result<&Frame, &DeviceError>,
    encoded_response: &[u8],
    length: usize,
) {
    let Ok(response) = Frame::parse(encoded_response) else {
        eprintln!(
            "virtual-yubihsm-worker: internal protocol response could not be parsed; transfer-length={length}"
        );
        return;
    };
    let Some((error_code, error)) = response_error(&response) else {
        return;
    };
    match request {
        Ok(request) => {
            let context = session_id(request)
                .map_or_else(String::new, |sid| format!("; session={sid}"));
            if request.command == CommandCode::SessionMessage as u8 {
                eprintln!(
                    "virtual-yubihsm-worker: secure session envelope failed before inner command dispatch: {} ({:#04x}){}",
                    error, error_code, context,
                );
            } else {
                eprintln!(
                    "virtual-yubihsm-worker: plain command {} ({:#04x}) failed: {} ({:#04x}){}",
                    command_name(request.command),
                    request.command,
                    error,
                    error_code,
                    context,
                );
            }
        }
        Err(parse_error) => eprintln!(
            "virtual-yubihsm-worker: protocol transfer failed before command dispatch: {parse_error} ({:#04x}); transfer-length={length}",
            *parse_error as u8,
        ),
    }
}

fn response_error(response: &Frame) -> Option<(u8, String)> {
    if response.command != 0x7f {
        return None;
    }
    let code = response.data.first().copied().unwrap_or(0xff);
    let description = DeviceError::from_byte(code).map_or_else(
        || "unknown device error".to_owned(),
        |error| error.to_string(),
    );
    Some((code, description))
}

fn command_name(command: u8) -> String {
    CommandCode::from_byte(command)
        .map_or_else(|| "Unknown".to_owned(), |command| format!("{command:?}"))
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
            Err(error) if endpoint_is_unavailable(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn endpoint_is_unavailable(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(11 | 19 | 32 | 108))
}

fn set_nonblocking(file: &File) -> io::Result<()> {
    // FunctionFS still blocks for a queued transfer while enabled. O_NONBLOCK
    // only prevents a new operation from sleeping while its endpoint is down.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
}
