//! Event-driven USB eject/reinsert control from the display HAT KEY3 button.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::thread::{self, JoinHandle};

const GPIO_V2_LINE_EVENT_SIZE: usize = 48;
const GPIO_V2_LINE_EVENT_ID_OFFSET: usize = 8;
const GPIO_V2_LINE_EVENT_RISING_EDGE: u32 = 1;
const GPIO_V2_LINE_EVENT_FALLING_EDGE: u32 = 2;

pub(crate) struct Controller {
    shutdown: UnixDatagram,
    reconnect: UnixDatagram,
    thread: JoinHandle<io::Result<()>>,
}

impl Controller {
    pub(crate) fn start(mut reconnect_lines: File) -> io::Result<Self> {
        set_nonblocking(&reconnect_lines)?;
        let (shutdown, receiver) = UnixDatagram::pair()?;
        let (reconnect_sender, reconnect) = UnixDatagram::pair()?;
        reconnect.set_nonblocking(true)?;
        reconnect_sender.set_nonblocking(true)?;
        let thread = thread::Builder::new()
            .name("yubihsm-buttons".to_owned())
            .spawn(move || button_loop(&mut reconnect_lines, receiver, reconnect_sender))?;
        Ok(Self {
            shutdown,
            reconnect,
            thread,
        })
    }

    pub(crate) fn reconnect_descriptor(&self) -> i32 {
        self.reconnect.as_raw_fd()
    }

    pub(crate) fn take_reconnect_transition(&self) -> io::Result<Option<bool>> {
        let mut byte = [0_u8; 1];
        loop {
            match self.reconnect.recv(&mut byte) {
                Ok(1) if byte[0] <= 1 => return Ok(Some(byte[0] != 0)),
                Ok(length) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid reconnect transition packet: length={length}"),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
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
            drain_reconnect_events(reconnect_lines, &reconnect)?;
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

fn drain_reconnect_events(lines: &mut File, notifier: &UnixDatagram) -> io::Result<()> {
    loop {
        let mut event = [0_u8; GPIO_V2_LINE_EVENT_SIZE];
        match lines.read(&mut event) {
            Ok(GPIO_V2_LINE_EVENT_SIZE) => {
                let id = u32::from_ne_bytes(
                    event[GPIO_V2_LINE_EVENT_ID_OFFSET..GPIO_V2_LINE_EVENT_ID_OFFSET + 4]
                        .try_into()
                        .unwrap(),
                );
                let state = match id {
                    GPIO_V2_LINE_EVENT_RISING_EDGE => Some(1),
                    GPIO_V2_LINE_EVENT_FALLING_EDGE => Some(0),
                    _ => None,
                };
                if let Some(state) = state {
                    match notifier.send(&[state]) {
                        Ok(1) => {}
                        Ok(length) => {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                format!("sent {length} reconnect-state bytes"),
                            ));
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error),
                    }
                }
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
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
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
