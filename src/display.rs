//! Physical status display for the virtual YubiHSM worker.

const COLOR_FRAME_SIZE: usize = 240 * 240 * 2;
const OLED_FRAME_SIZE: usize = 128 * 64 / 8;
const LED_OFF_FRAME: &[u8; COLOR_FRAME_SIZE] = include_bytes!("../assets/yubihsm-led-off.rgb565");
const LED_ON_FRAME: &[u8; COLOR_FRAME_SIZE] = include_bytes!("../assets/yubihsm-led-on.rgb565");
const OLED_LED_OFF_FRAME: &[u8; OLED_FRAME_SIZE] =
    include_bytes!("../assets/yubihsm-oled-led-off.mono1");
const OLED_LED_ON_FRAME: &[u8; OLED_FRAME_SIZE] =
    include_bytes!("../assets/yubihsm-oled-led-on.mono1");

#[cfg(target_os = "linux")]
use display_backends::indicator::{
    AttentionGuard, Cadence, CommandGuard, Controller as IndicatorController, IdlePolicy,
    IndicatorRenderer, Policy,
};
#[cfg(target_os = "linux")]
use display_backends::{Backend, Display};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::sync::{
    mpsc::{self, Receiver, RecvTimeoutError, Sender},
    Arc, Mutex,
};
#[cfg(target_os = "linux")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const BUSY_CADENCE: Cadence = Cadence::new(Duration::from_millis(67), Duration::from_millis(33));
#[cfg(target_os = "linux")]
const IDLE_CADENCE: Cadence =
    Cadence::new(Duration::from_millis(1_500), Duration::from_millis(1_500));
#[cfg(target_os = "linux")]
const MINIMUM_EDGE: Duration = Duration::from_millis(8);

#[cfg(target_os = "linux")]
const fn indicator_policy() -> Policy {
    Policy::new(
        BUSY_CADENCE,
        IdlePolicy::Periodic(IDLE_CADENCE),
        MINIMUM_EDGE,
    )
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct Activity {
    inner: display_backends::indicator::Activity,
    sender: Sender<Command>,
}

#[cfg(target_os = "linux")]
impl Activity {
    pub(crate) fn begin(&self) -> CommandGuard {
        self.inner.begin()
    }

    pub(crate) fn identify(&self, seconds: u8) {
        let _ = self.sender.send(Command::Identify(seconds));
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct Controller {
    sender: Sender<Command>,
    activity: display_backends::indicator::Activity,
    thread: JoinHandle<io::Result<()>>,
}

#[cfg(target_os = "linux")]
impl Controller {
    pub(crate) fn start(bus: File, control: File, kind: crate::DisplayKind) -> io::Result<Self> {
        let hardware = Arc::new(Mutex::new(Hardware::new(bus, control, kind)));
        let indicator = IndicatorController::start(
            indicator_policy(),
            HardwareRenderer {
                hardware: Arc::clone(&hardware),
            },
            "yubihsm-indicator",
        )?;
        let activity = indicator.activity();
        let (sender, receiver) = mpsc::channel();
        let display_activity = activity.clone();
        let thread = thread::Builder::new()
            .name("yubihsm-display".to_owned())
            .spawn(move || display_loop(indicator, hardware, receiver, display_activity))?;
        Ok(Self {
            sender,
            activity,
            thread,
        })
    }

    pub(crate) fn activity(&self) -> Activity {
        Activity {
            inner: self.activity.clone(),
            sender: self.sender.clone(),
        }
    }

    pub(crate) fn personality_present(&self) -> io::Result<()> {
        send_command(&self.sender, Command::PersonalityPresent)
    }

    pub(crate) fn personality_absent(&self) -> io::Result<()> {
        send_command(&self.sender, Command::PersonalityAbsent)
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
            .map_err(|_| io::Error::other("YubiHSM display thread panicked"))?
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum Command {
    Identify(u8),
    PersonalityPresent,
    PersonalityAbsent,
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
    indicator: IndicatorController,
    hardware: Arc<Mutex<Hardware>>,
    receiver: Receiver<Command>,
    activity: display_backends::indicator::Activity,
) -> io::Result<()> {
    let mut personality_present = false;
    let mut bound = false;
    let mut suspended = false;
    let mut identify_until: Option<Instant> = None;
    let mut identify_guard: Option<AttentionGuard> = None;

    loop {
        let received = match identify_until {
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
                identify_until = None;
                drop(identify_guard.take());
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => Command::Shutdown,
        };

        match command {
            Command::Identify(seconds) => {
                if personality_present && bound && !suspended && seconds != 0 {
                    drop(identify_guard.take());
                    identify_guard = Some(activity.attention(BUSY_CADENCE)?);
                    identify_until = Some(Instant::now() + Duration::from_secs(u64::from(seconds)));
                }
            }
            Command::PersonalityPresent => {
                personality_present = true;
                bound = false;
                suspended = false;
                identify_until = None;
                drop(identify_guard.take());
                indicator.disable()?;
                lock_hardware(&hardware)?.render(false);
            }
            Command::PersonalityAbsent => {
                personality_present = false;
                bound = false;
                suspended = false;
                identify_until = None;
                drop(identify_guard.take());
                let result = indicator.disable();
                lock_hardware(&hardware)?.turn_off("USB personality absent");
                result?;
            }
            Command::Bind => {
                bound = true;
                suspended = false;
                identify_until = None;
                drop(identify_guard.take());
                if personality_present {
                    lock_hardware(&hardware)?.render(false);
                    indicator.enable()?;
                }
            }
            Command::Unbind => {
                bound = false;
                suspended = false;
                identify_until = None;
                drop(identify_guard.take());
                indicator.disable()?;
                if personality_present {
                    lock_hardware(&hardware)?.render(false);
                }
            }
            Command::Suspend => {
                suspended = true;
                identify_until = None;
                drop(identify_guard.take());
                indicator.disable()?;
                if personality_present {
                    lock_hardware(&hardware)?.render(false);
                }
            }
            Command::Resume => {
                if personality_present && bound && suspended {
                    suspended = false;
                    lock_hardware(&hardware)?.render(false);
                    indicator.enable()?;
                }
            }
            Command::Shutdown => {
                drop(identify_guard.take());
                let result = indicator.shutdown();
                lock_hardware(&hardware)?.turn_off("worker shutdown");
                return result;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn lock_hardware(hardware: &Mutex<Hardware>) -> io::Result<std::sync::MutexGuard<'_, Hardware>> {
    hardware
        .lock()
        .map_err(|_| io::Error::other("YubiHSM display lock poisoned"))
}

#[cfg(target_os = "linux")]
struct HardwareRenderer {
    hardware: Arc<Mutex<Hardware>>,
}

#[cfg(target_os = "linux")]
impl IndicatorRenderer for HardwareRenderer {
    fn set_indicator(&mut self, lit: bool) -> io::Result<()> {
        lock_hardware(&self.hardware)?.render(lit);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct Hardware {
    bus: File,
    control: File,
    kind: crate::DisplayKind,
    display: Option<Display>,
    error_reported: bool,
}

#[cfg(target_os = "linux")]
impl Hardware {
    fn new(bus: File, control: File, kind: crate::DisplayKind) -> Self {
        Self {
            bus,
            control,
            kind,
            display: None,
            error_reported: false,
        }
    }

    fn render(&mut self, led_on: bool) {
        if self.display.is_none() {
            let backend = match self.kind {
                crate::DisplayKind::St7789Spi => Backend::St7789Spi,
                crate::DisplayKind::Sh1106Spi => Backend::Sh1106Spi,
            };
            match Display::from_raw_fds(
                backend,
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
        let frame: &[u8] = match (self.kind, led_on) {
            (crate::DisplayKind::St7789Spi, false) => LED_OFF_FRAME,
            (crate::DisplayKind::St7789Spi, true) => LED_ON_FRAME,
            (crate::DisplayKind::Sh1106Spi, false) => OLED_LED_OFF_FRAME,
            (crate::DisplayKind::Sh1106Spi, true) => OLED_LED_ON_FRAME,
        };
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
        assert_eq!(LED_OFF_FRAME.len(), COLOR_FRAME_SIZE);
        assert_eq!(LED_ON_FRAME.len(), COLOR_FRAME_SIZE);
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

    #[test]
    fn oled_frames_are_native_monochrome_images() {
        assert_eq!(OLED_LED_OFF_FRAME.len(), OLED_FRAME_SIZE);
        assert_eq!(OLED_LED_ON_FRAME.len(), OLED_FRAME_SIZE);
        assert_ne!(OLED_LED_OFF_FRAME, OLED_LED_ON_FRAME);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn indicator_policy_preserves_yubihsm_cadences() {
        let policy = indicator_policy();
        assert_eq!(policy.busy.on, Duration::from_millis(67));
        assert_eq!(policy.busy.off, Duration::from_millis(33));
        assert_eq!(
            policy.idle,
            IdlePolicy::Periodic(Cadence::new(
                Duration::from_millis(1_500),
                Duration::from_millis(1_500)
            ))
        );
        assert_eq!(policy.minimum_edge, Duration::from_millis(8));
    }
}
