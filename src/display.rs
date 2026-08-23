//! Physical ST7789 status display for the virtual YubiHSM worker.

const FRAME_SIZE: usize = 240 * 240 * 2;
const LED_OFF_FRAME: &[u8; FRAME_SIZE] = include_bytes!("../assets/yubihsm-led-off.rgb565");
const LED_ON_FRAME: &[u8; FRAME_SIZE] = include_bytes!("../assets/yubihsm-led-on.rgb565");

#[cfg(target_os = "linux")]
use display_backends::{Backend, Display};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const ACTIVITY_HOLD: Duration = Duration::from_millis(90);
#[cfg(target_os = "linux")]
const NORMAL_BLINK_HALF_PERIOD: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const IDENTIFY_BLINK_HALF_PERIOD: Duration = Duration::from_millis(125);

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct Activity {
    sender: Sender<Command>,
    activity_pending: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
impl Activity {
    pub(crate) fn pulse(&self) {
        if self.activity_pending.swap(true, Ordering::AcqRel) {
            return;
        }
        if self.sender.send(Command::Activity).is_err() {
            self.activity_pending.store(false, Ordering::Release);
        }
    }

    pub(crate) fn identify(&self, seconds: u8) {
        let _ = self.sender.send(Command::Identify(seconds));
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct Controller {
    sender: Sender<Command>,
    activity_pending: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl Controller {
    pub(crate) fn start(bus: File, control: File) -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let activity_pending = Arc::new(AtomicBool::new(false));
        let display_activity_pending = activity_pending.clone();
        let thread = thread::Builder::new()
            .name("yubihsm-display".to_owned())
            .spawn(move || display_loop(bus, control, receiver, display_activity_pending))?;
        Ok(Self {
            sender,
            activity_pending,
            thread,
        })
    }

    pub(crate) fn activity(&self) -> Activity {
        Activity {
            sender: self.sender.clone(),
            activity_pending: self.activity_pending.clone(),
        }
    }

    pub(crate) fn bind(&self) -> io::Result<()> {
        send_command(&self.sender, Command::Bind)
    }

    pub(crate) fn unbind(&self) -> io::Result<()> {
        send_command(&self.sender, Command::Unbind)
    }

    pub(crate) fn suspend(&self) -> io::Result<()> {
        send_command(&self.sender, Command::Suspend)
    }

    pub(crate) fn resume(&self) -> io::Result<()> {
        send_command(&self.sender, Command::Resume)
    }

    pub(crate) fn shutdown(self) -> io::Result<()> {
        let _ = self.sender.send(Command::Shutdown);
        self.thread
            .join()
            .map_err(|_| io::Error::other("YubiHSM display thread panicked"))
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum Command {
    Activity,
    Identify(u8),
    Bind,
    Unbind,
    Suspend,
    Resume,
    Shutdown,
}

#[cfg(target_os = "linux")]
fn send_command(sender: &Sender<Command>, command: Command) -> io::Result<()> {
    sender
        .send(command)
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "YubiHSM display thread stopped"))
}

#[cfg(target_os = "linux")]
fn display_loop(
    bus: File,
    control: File,
    receiver: Receiver<Command>,
    activity_pending: Arc<AtomicBool>,
) {
    let mut hardware = Hardware::new(bus, control);
    let mut bound = false;
    let mut suspended = false;
    let mut normal_lit = false;
    let mut normal_due = None;
    let mut activity_until = None;
    let mut identify_until = None;
    let mut identify_due = None;
    let mut identify_lit = false;

    loop {
        let deadline = if identify_until.is_some() {
            earliest(identify_due, identify_until)
        } else {
            earliest(normal_due, activity_until)
        };
        let received = match deadline {
            Some(deadline) => receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map(Some),
            None => receiver
                .recv()
                .map(Some)
                .map_err(|_| RecvTimeoutError::Disconnected),
        };
        let command = match received {
            Ok(Some(command)) => command,
            Ok(None) => unreachable!(),
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                if let Some(until) = identify_until {
                    if now >= until {
                        identify_until = None;
                        identify_due = None;
                        identify_lit = false;
                        normal_lit = false;
                        normal_due = Some(now + NORMAL_BLINK_HALF_PERIOD);
                        hardware.render(false);
                    } else if identify_due.is_some_and(|due| now >= due) {
                        identify_lit = !identify_lit;
                        hardware.render(identify_lit);
                        identify_due = Some(now + IDENTIFY_BLINK_HALF_PERIOD);
                    }
                } else {
                    let activity_ended = activity_until.is_some_and(|until| now >= until);
                    if activity_ended {
                        activity_until = None;
                    }
                    let normal_changed = normal_due.is_some_and(|due| now >= due);
                    if normal_changed {
                        normal_lit = !normal_lit;
                        normal_due = Some(now + NORMAL_BLINK_HALF_PERIOD);
                    }
                    if activity_ended || (normal_changed && activity_until.is_none()) {
                        hardware.render(normal_lit);
                    }
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => Command::Shutdown,
        };

        match command {
            Command::Activity => {
                activity_pending.store(false, Ordering::Release);
                if bound && !suspended && identify_until.is_none() {
                    hardware.render(!normal_lit);
                    activity_until = Some(Instant::now() + ACTIVITY_HOLD);
                }
            }
            Command::Identify(seconds) => {
                if bound && !suspended && seconds != 0 {
                    let now = Instant::now();
                    identify_lit = true;
                    identify_until = Some(now + Duration::from_secs(u64::from(seconds)));
                    identify_due = Some(now + IDENTIFY_BLINK_HALF_PERIOD);
                    normal_due = None;
                    activity_until = None;
                    hardware.render(true);
                }
            }
            Command::Bind => {
                bound = true;
                suspended = false;
                normal_lit = false;
                normal_due = Some(Instant::now() + NORMAL_BLINK_HALF_PERIOD);
                activity_until = None;
                identify_until = None;
                identify_due = None;
                hardware.render(false);
            }
            Command::Unbind => {
                bound = false;
                suspended = false;
                normal_due = None;
                activity_until = None;
                identify_until = None;
                identify_due = None;
                hardware.turn_off("USB unbind");
            }
            Command::Suspend => {
                suspended = true;
                normal_due = None;
                activity_until = None;
                identify_until = None;
                identify_due = None;
                if bound {
                    hardware.turn_off("USB suspend");
                }
            }
            Command::Resume => {
                if bound && suspended {
                    suspended = false;
                    normal_lit = false;
                    normal_due = Some(Instant::now() + NORMAL_BLINK_HALF_PERIOD);
                    hardware.render(false);
                }
            }
            Command::Shutdown => {
                hardware.turn_off("worker shutdown");
                break;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn earliest(first: Option<Instant>, second: Option<Instant>) -> Option<Instant> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[cfg(target_os = "linux")]
struct Hardware {
    bus: File,
    control: File,
    display: Option<Display>,
    error_reported: bool,
}

#[cfg(target_os = "linux")]
impl Hardware {
    fn new(bus: File, control: File) -> Self {
        Self {
            bus,
            control,
            display: None,
            error_reported: false,
        }
    }

    fn render(&mut self, led_on: bool) {
        if self.display.is_none() {
            match Display::from_raw_fds(
                Backend::St7789Spi,
                self.bus.as_raw_fd(),
                Some(self.control.as_raw_fd()),
            ) {
                Ok(display) => {
                    self.display = Some(display);
                    self.error_reported = false;
                }
                Err(error) => {
                    self.report_error("initialization", &error);
                    return;
                }
            }
        }
        let frame = if led_on { LED_ON_FRAME } else { LED_OFF_FRAME };
        if let Err(error) = self.display.as_mut().unwrap().write_native_frame(frame) {
            self.report_error("frame write", &error);
        }
    }

    fn turn_off(&mut self, reason: &str) {
        let Some(mut display) = self.display.take() else {
            return;
        };
        if let Err(error) = display.shutdown() {
            self.report_error(reason, &error);
        }
    }

    fn report_error(&mut self, operation: &str, error: &io::Error) {
        if !self.error_reported {
            eprintln!("virtual-yubihsm-worker: display {operation} failed: {error}");
        }
        self.error_reported = true;
        self.display = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_frames_change_only_the_strap_hole_led() {
        assert_eq!(LED_OFF_FRAME.len(), FRAME_SIZE);
        assert_eq!(LED_ON_FRAME.len(), FRAME_SIZE);
        let mut changed = 0;
        for (index, (off, on)) in LED_OFF_FRAME
            .chunks_exact(2)
            .zip(LED_ON_FRAME.chunks_exact(2))
            .enumerate()
        {
            if off == on {
                continue;
            }
            changed += 1;
            let x = index % 240;
            let y = index / 240;
            assert!((103..=136).contains(&x));
            assert!((37..=54).contains(&y));
        }
        assert!((100..600).contains(&changed));
    }
}
