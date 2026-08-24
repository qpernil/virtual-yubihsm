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
use display_backends::{Backend, Display};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc::{self, Receiver, RecvTimeoutError, Sender},
    Arc,
};
#[cfg(target_os = "linux")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const ACTIVITY_LED_ON_HOLD: Duration = Duration::from_millis(67);
#[cfg(target_os = "linux")]
const ACTIVITY_LED_OFF_HOLD: Duration = Duration::from_millis(33);
#[cfg(target_os = "linux")]
const NORMAL_BLINK_HALF_PERIOD: Duration = Duration::from_millis(1_500);

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct Activity {
    state: Arc<ActivityState>,
}

#[cfg(target_os = "linux")]
struct ActivityState {
    sender: Sender<Command>,
    active_count: AtomicUsize,
    notification_pending: AtomicBool,
}

#[cfg(target_os = "linux")]
impl ActivityState {
    fn notify(&self) {
        if !self.notification_pending.swap(true, Ordering::AcqRel)
            && self.sender.send(Command::ActivityChanged).is_err()
        {
            self.notification_pending.store(false, Ordering::Release);
        }
    }
}

#[cfg(target_os = "linux")]
impl Activity {
    pub(crate) fn begin(&self) -> ActivityGuard {
        let previous = self
            .state
            .active_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_add(1))
            })
            .unwrap();
        if previous == 0 {
            self.state.notify();
        }
        ActivityGuard {
            state: Arc::clone(&self.state),
        }
    }

    pub(crate) fn identify(&self, seconds: u8) {
        let _ = self.state.sender.send(Command::Identify(seconds));
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct ActivityGuard {
    state: Arc<ActivityState>,
}

#[cfg(target_os = "linux")]
impl Drop for ActivityGuard {
    fn drop(&mut self) {
        let previous = self
            .state
            .active_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            })
            .unwrap();
        if previous == 1 {
            self.state.notify();
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct Controller {
    sender: Sender<Command>,
    activity_state: Arc<ActivityState>,
    thread: JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl Controller {
    pub(crate) fn start(bus: File, control: File, kind: crate::DisplayKind) -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let activity_state = Arc::new(ActivityState {
            sender: sender.clone(),
            active_count: AtomicUsize::new(0),
            notification_pending: AtomicBool::new(false),
        });
        let display_activity_state = Arc::clone(&activity_state);
        let thread = thread::Builder::new()
            .name("yubihsm-display".to_owned())
            .spawn(move || display_loop(bus, control, kind, receiver, display_activity_state))?;
        Ok(Self {
            sender,
            activity_state,
            thread,
        })
    }

    pub(crate) fn activity(&self) -> Activity {
        Activity {
            state: Arc::clone(&self.activity_state),
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
            .map_err(|_| io::Error::other("YubiHSM display thread panicked"))
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum Command {
    ActivityChanged,
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
    bus: File,
    control: File,
    kind: crate::DisplayKind,
    receiver: Receiver<Command>,
    activity_state: Arc<ActivityState>,
) {
    let mut hardware = Hardware::new(bus, control, kind);
    let mut personality_present = false;
    let mut bound = false;
    let mut suspended = false;
    let mut lit = false;
    let mut activity_count = 0_usize;
    let mut identify_until = None;
    let mut blink_due = None;

    loop {
        let deadline = earliest(blink_due, identify_until);
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
                if identify_until.is_some_and(|until| now >= until) {
                    identify_until = None;
                    if activity_count == 0 {
                        blink_due = selected_blink_delay(
                            personality_present,
                            bound,
                            suspended,
                            activity_count,
                            identify_until,
                            lit,
                        )
                        .map(|period| now + period);
                    }
                } else if blink_due.is_some_and(|due| now >= due) {
                    invert_led(&mut hardware, &mut lit);
                    blink_due = selected_blink_delay(
                        personality_present,
                        bound,
                        suspended,
                        activity_count,
                        identify_until,
                        lit,
                    )
                    .map(|period| Instant::now() + period);
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => Command::Shutdown,
        };

        match command {
            Command::ActivityChanged => {
                activity_state
                    .notification_pending
                    .store(false, Ordering::Release);
                let current_count = activity_state.active_count.load(Ordering::Acquire);
                let was_active = activity_count != 0;
                let is_active = current_count != 0;
                activity_count = current_count;
                if was_active != is_active {
                    if personality_present && bound && !suspended {
                        invert_led(&mut hardware, &mut lit);
                    }
                    let now = Instant::now();
                    if identify_until.is_some_and(|until| now >= until) {
                        identify_until = None;
                    }
                    blink_due = selected_blink_delay(
                        personality_present,
                        bound,
                        suspended,
                        activity_count,
                        identify_until,
                        lit,
                    )
                    .map(|period| now + period);
                }
            }
            Command::Identify(seconds) => {
                if personality_present && bound && !suspended && seconds != 0 {
                    let now = Instant::now();
                    identify_until = Some(now + Duration::from_secs(u64::from(seconds)));
                    if activity_count == 0 {
                        blink_due = Some(now + activity_blink_delay(lit));
                    }
                }
            }
            Command::PersonalityPresent => {
                personality_present = true;
                bound = false;
                suspended = false;
                lit = false;
                activity_count = 0;
                identify_until = None;
                blink_due = None;
                hardware.render(false);
            }
            Command::PersonalityAbsent => {
                personality_present = false;
                bound = false;
                suspended = false;
                activity_count = 0;
                identify_until = None;
                blink_due = None;
                lit = false;
                hardware.turn_off("USB personality absent");
            }
            Command::Bind => {
                bound = true;
                suspended = false;
                lit = false;
                activity_count = 0;
                identify_until = None;
                blink_due = personality_present.then(|| Instant::now() + NORMAL_BLINK_HALF_PERIOD);
                if personality_present {
                    hardware.render(false);
                }
            }
            Command::Unbind => {
                bound = false;
                suspended = false;
                activity_count = 0;
                identify_until = None;
                blink_due = None;
                if personality_present {
                    lit = false;
                    hardware.render(false);
                }
            }
            Command::Suspend => {
                suspended = true;
                identify_until = None;
                blink_due = None;
                if personality_present {
                    lit = false;
                    hardware.render(false);
                }
            }
            Command::Resume => {
                if personality_present && bound && suspended {
                    suspended = false;
                    lit = false;
                    hardware.render(false);
                    activity_count = activity_state.active_count.load(Ordering::Acquire);
                    blink_due = selected_blink_delay(
                        personality_present,
                        bound,
                        suspended,
                        activity_count,
                        identify_until,
                        lit,
                    )
                    .map(|period| Instant::now() + period);
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
fn invert_led(hardware: &mut Hardware, lit: &mut bool) {
    *lit = !*lit;
    hardware.render(*lit);
}

#[cfg(target_os = "linux")]
fn selected_blink_delay(
    personality_present: bool,
    bound: bool,
    suspended: bool,
    activity_count: usize,
    identify_until: Option<Instant>,
    lit: bool,
) -> Option<Duration> {
    if !personality_present || !bound || suspended {
        None
    } else if activity_count != 0 || identify_until.is_some() {
        Some(activity_blink_delay(lit))
    } else {
        Some(NORMAL_BLINK_HALF_PERIOD)
    }
}

#[cfg(target_os = "linux")]
fn activity_blink_delay(lit: bool) -> Duration {
    if lit {
        ACTIVITY_LED_ON_HOLD
    } else {
        ACTIVITY_LED_OFF_HOLD
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
    fn activity_guard_tracks_current_state_without_queuing_history() {
        let (sender, receiver) = mpsc::channel();
        let state = Arc::new(ActivityState {
            sender,
            active_count: AtomicUsize::new(0),
            notification_pending: AtomicBool::new(false),
        });
        let activity = Activity {
            state: Arc::clone(&state),
        };

        let first = activity.begin();
        let second = activity.begin();
        assert_eq!(state.active_count.load(Ordering::Acquire), 2);
        assert!(matches!(receiver.recv().unwrap(), Command::ActivityChanged));
        assert!(receiver.try_recv().is_err());

        state.notification_pending.store(false, Ordering::Release);
        drop(first);
        assert_eq!(state.active_count.load(Ordering::Acquire), 1);
        assert!(receiver.try_recv().is_err());

        drop(second);
        assert_eq!(state.active_count.load(Ordering::Acquire), 0);
        assert!(matches!(receiver.recv().unwrap(), Command::ActivityChanged));
        assert!(receiver.try_recv().is_err());

        assert_eq!(ACTIVITY_LED_ON_HOLD, Duration::from_millis(67));
        assert_eq!(ACTIVITY_LED_OFF_HOLD, Duration::from_millis(33));
        assert_eq!(
            ACTIVITY_LED_ON_HOLD + ACTIVITY_LED_OFF_HOLD,
            Duration::from_millis(100)
        );
        assert!(ACTIVITY_LED_ON_HOLD < NORMAL_BLINK_HALF_PERIOD);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn blink_scheduler_selects_stopped_idle_and_activity_cadences() {
        let now = Instant::now();
        assert_eq!(selected_blink_delay(true, true, true, 0, None, false), None);
        assert_eq!(
            selected_blink_delay(true, false, false, 0, None, false),
            None
        );
        assert_eq!(
            selected_blink_delay(true, true, false, 0, None, false),
            Some(NORMAL_BLINK_HALF_PERIOD)
        );
        assert_eq!(
            selected_blink_delay(true, true, false, 1, None, true),
            Some(ACTIVITY_LED_ON_HOLD)
        );
        assert_eq!(
            selected_blink_delay(true, true, false, 0, Some(now), false),
            Some(ACTIVITY_LED_OFF_HOLD)
        );
    }
}
