//! Event-driven USB eject/reinsert control from the display HAT KEY3 button.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};

const GPIO_V2_LINE_EVENT_SIZE: usize = 48;
const GPIO_V2_LINE_EVENT_ID_OFFSET: usize = 8;
const GPIO_V2_LINE_EVENT_RISING_EDGE: u32 = 1;
const GPIO_V2_LINE_EVENT_FALLING_EDGE: u32 = 2;

pub(crate) struct Controller {
    shutdown: UnixDatagram,
    reconnect: UnixDatagram,
    reconnect_pressed: Arc<AtomicBool>,
    thread: JoinHandle<io::Result<()>>,
}

impl Controller {
    pub(crate) fn start(mut reconnect_lines: File) -> io::Result<Self> {
        let reconnect_pressed = Arc::new(AtomicBool::new(read_pressed(&reconnect_lines)?));
        set_nonblocking(&reconnect_lines)?;
        let (shutdown, receiver) = UnixDatagram::pair()?;
        let (reconnect_sender, reconnect) = UnixDatagram::pair()?;
        reconnect.set_nonblocking(true)?;
        reconnect_sender.set_nonblocking(true)?;
        let thread_state = Arc::clone(&reconnect_pressed);
        let thread = thread::Builder::new()
            .name("yubihsm-buttons".to_owned())
            .spawn(move || {
                button_loop(
                    &mut reconnect_lines,
                    receiver,
                    reconnect_sender,
                    thread_state,
                )
            })?;
        Ok(Self {
            shutdown,
            reconnect,
            reconnect_pressed,
            thread,
        })
    }

    pub(crate) fn reconnect_descriptor(&self) -> i32 {
        self.reconnect.as_raw_fd()
    }

    pub(crate) fn reconnect_pressed(&self) -> bool {
        self.reconnect_pressed.load(Ordering::Acquire)
    }

    pub(crate) fn take_reconnect_state(&self) -> io::Result<bool> {
        let mut byte = [0_u8; 1];
        loop {
            match self.reconnect.recv(&mut byte) {
                Ok(1) if byte[0] == 0 => {}
                Ok(length) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid reconnect transition packet: length={length}"),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(self.reconnect_pressed())
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn shutdown(self) -> io::Result<()> {
        let _ = self.shutdown.send(&[0]);
        self.thread
            .join()
            .map_err(|_| io::Error::other("YubiHSM reconnect-button thread panicked"))?
    }
}

fn button_loop(
    reconnect_lines: &mut File,
    shutdown: UnixDatagram,
    reconnect: UnixDatagram,
    reconnect_pressed: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut poll_fds = [
        libc::pollfd {
            fd: reconnect_lines.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: shutdown.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: poll_fds contains valid descriptors for the duration of poll.
        let result = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, -1) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if poll_fds[1].revents & libc::POLLIN != 0 {
            return Ok(());
        }
        if poll_fds[0].revents & libc::POLLIN != 0 {
            drain_reconnect_events(reconnect_lines, &reconnect, &reconnect_pressed)?;
        }
        for descriptor in poll_fds {
            let unexpected = descriptor.revents & !libc::POLLIN;
            if unexpected != 0 {
                return Err(io::Error::other(format!(
                    "button descriptor reported poll events 0x{unexpected:x}"
                )));
            }
        }
    }
}

fn drain_reconnect_events(
    lines: &mut File,
    notifier: &UnixDatagram,
    pressed: &AtomicBool,
) -> io::Result<()> {
    let mut saw_transition = false;
    loop {
        let mut event = [0_u8; GPIO_V2_LINE_EVENT_SIZE];
        match lines.read(&mut event) {
            Ok(GPIO_V2_LINE_EVENT_SIZE) => {
                let id = u32::from_ne_bytes(
                    event[GPIO_V2_LINE_EVENT_ID_OFFSET..GPIO_V2_LINE_EVENT_ID_OFFSET + 4]
                        .try_into()
                        .unwrap(),
                );
                saw_transition |= matches!(
                    id,
                    GPIO_V2_LINE_EVENT_RISING_EDGE | GPIO_V2_LINE_EVENT_FALLING_EDGE
                );
            }
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "reconnect-button descriptor closed",
                ));
            }
            Ok(length) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("partial GPIO edge event: {length} bytes"),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if saw_transition {
        let current = read_pressed(lines)?;
        if pressed.swap(current, Ordering::AcqRel) != current {
            match notifier.send(&[0]) {
                Ok(1) => {}
                Ok(length) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!("sent {length} reconnect notification bytes"),
                    ));
                }
                // A queued notification already wakes the consumer, which then
                // reads the latest atomic level.
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn read_pressed(lines: &File) -> io::Result<bool> {
    let mut values = gpiocdev_uapi::v2::LineValues { bits: 0, mask: 1 };
    gpiocdev_uapi::v2::get_line_values(lines, &mut values)
        .map_err(|error| io::Error::other(format!("read reconnect-button level: {error}")))?;
    values
        .get(0)
        .ok_or_else(|| io::Error::other("reconnect-button level was not returned"))
}

fn set_nonblocking(file: &File) -> io::Result<()> {
    // SAFETY: fcntl operates on a valid inherited descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor remains valid and F_SETFL accepts these flags.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
