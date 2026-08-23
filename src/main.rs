//! Thin worker entry point. The FunctionFS adapter is intentionally kept out
//! of `virtual-yubihsm-core`; the next implementation layer will connect this
//! binary to the already established usb-gadget-supervisor worker protocol.

fn main() {
    if std::env::args().any(|argument| argument == "--help" || argument == "-h") {
        println!(
            "Usage: virtual-yubihsm-worker [--serial DECIMAL]\n\n\
             Unprivileged YubiHSM 2 protocol worker for usb-gadget-supervisor."
        );
        return;
    }
    eprintln!("virtual-yubihsm-worker: FunctionFS adapter is not enabled in this build yet");
    std::process::exit(2);
}
