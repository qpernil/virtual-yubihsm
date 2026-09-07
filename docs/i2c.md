# Experimental I2C transport

I2C is a niche experimental frontend. `virtual-yubihsm-i2c` exposes the real
`virtual-yubihsm-core` protocol through
the Linux character device provided by
[`raspberry-pi-i2c-target`](https://github.com/qpernil/raspberry-pi-i2c-target).
It is a transport frontend, not a mock: authentication, secure sessions,
objects, cryptographic commands, options, audit records, and persistent state
all use the same core as the USB-gadget and embedded-connector frontends.

## Oscilloscope experiments

This frontend extends the same Raspberry Pi bench work as the
[Virtual Trezor I2C display plan](https://github.com/qpernil/virtual-trezor/blob/main/docs/i2c-display-plan.md),
whose Siglent SDS824X HD observes SCL, SDA, and timing markers. The HSM adds
request/response traffic and READY signaling. Use those signals to
inspect response latency and staged-read completion, and measure the physical
SCL rate rather than relying on the configured adapter rate. The display notes
describe the Pi 4 clock-scaling discrepancy observed with the scope.

The controller-side
[I2C experiment notes](https://github.com/qpernil/pkcs11rs/blob/master/docs/i2c-stability.md#oscilloscope-experiments)
and target-driver
[hardware validation plan](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/hardware-test-plan.md)
describe the exchange contract, signal-integrity checks, and evidence to retain.

## Wire exchange

Response mode requires an active-low, open-drain READY GPIO and driver ABI 3.
Upgrade the controller, driver and HSM frontend together. Receive-only display
workloads do not require READY and retain their 1,024-record receive ring.

The controller holds the physical bus lock while writing a complete request.
The driver invalidates the previous result when new input arrives and clears
old transmit data after the receive burst ends. It then acknowledges cleanup
with a deasserting READY edge (physical rising edge). If READY was already
inactive, a short assertion ensures this edge still exists; the assertion is
held for 20 µs so the controller GPIO can latch it. During this request phase,
that pulse is an acknowledgment, not a response. Arm rising-only GPIO detection before writing and discard stale events. After
acknowledgment, arm falling-only detection and check the current response level.
A reply arriving before reconfiguration stays asserted; a later reply wakes the
waiter. Linux both-edge detection may classify an interrupt by sampling the pin
in its deferred handler, mislabeling a short inactive interval. Single-edge
selection avoids that ambiguity without extending response timing.

After the acknowledgment the controller releases the bus, waits for the next
READY assertion, then reacquires the bus to read the exact response length.
The driver queues only response bytes. READY stays asserted after the read;
there is no guard byte, fallback marker, drain timeout, or post-read reset.
The next request clears any leftovers, including abandoned reads. No peripheral
reset occurs while another target is computing or publishing its response.

One worker executes requests sequentially. With READY, the driver retains only
one pending request, replacing it when newer input arrives. A worker response
is published only if it belongs to the latest receive generation; a superseded
write succeeds but discards its bytes. This cannot undo an executed operation's
side effects. A controller must not automatically replay uncertain commands.
A read and its corresponding write belong to one worker; concurrent worker
reads are not supported. Requests must have a STOP and wait for acknowledgment
before another request; arbitrary adjacent writes can merge into one record.

The bus lock also covers the entire header/body read. It does not cover HSM
computation, so targets with separate READY lines can progress concurrently.
All controllers sharing the physical bus must cooperate in this lock; other
kernel drivers and raw clients do not do so automatically. Administrative
activation, close and unload still require quiescent controller traffic.

## Manual bench test

Use a Linux controller with `/dev/i2c-1` enabled and a Pi 3B/3B+ or Pi 4B
target. Follow the driver's
[wiring table](https://github.com/qpernil/raspberry-pi-i2c-target#wiring)
for SDA, SCL, and common ground; power the boards separately. Connect target GPIO17 to the configured controller
READY input (GPIO23 in this example). Stop any service
already using `/dev/bsc-target0` before a foreground run.

Use current builds of `virtual-yubihsm-i2c`, `usb-gadget-supervisor`, and
`target-driver`. Install the [device profile](#profile-based-service) once,
using the existing `per` account. No device group or dedicated account is
required. On small ARM64 targets, each repository provides a checksummed
convenience binary under `prebuilt/aarch64/`; substitute that path for
`target/release/` in these recipes. The kernel module still needs a local C build.

**Target Pi:** from `raspberry-pi-i2c-target`, build as your normal user:

```sh
cargo build --release --locked --bin target-driver
make -C kernel
```

The kernel build needs a C toolchain, matching running-kernel headers, and
`dtc`. The runtime needs `dtoverlay` and the Linux module tools. Start the
compiled launcher:

```sh
sudo ./target/release/target-driver --profile virtual-yubihsm-i2c --ready-gpio 17 0x24 ./kernel
```

`target-driver` detects Pi 3 versus Pi 4, loads the matching overlay and module,
and starts the installed supervisor with that profile. It does not open the
character device itself in profile mode. The supervisor opens `/dev/bsc-target0`,
passes it as FD 3, and runs the HSM as `per`. The HSM never loads the driver or
reads the profile; its `--inherited-device` option consumes FD 3. Driver setup
and cleanup are implemented in `target-driver`.

Ctrl-C stops the supervisor and HSM, allowing pending state to flush, then
unloads the module and overlay. Existing loaded targets are refused. A failed
module removal leaves the overlay attached. SIGKILL can leave an inert module
and overlay; use `target-driver --unload` after the worker has stopped.
State persists in the profile's state directory; first startup creates
factory-default HSM state, and later starts reuse it.

Set serial and state location in the profile, and pass the I2C address to `target-driver` explicitly; its ordinary echo-test default is
`0x13`, while these HSM examples use `0x24`.

**Controller:** ensure your account can access the I2C bus and any READY GPIO.
From `pkcs11rs`, build and run the native connector:

```sh
cargo build --release --locked -p pkcs11rs-connector --features experimental-i2c
./target/release/pkcs11rs-connector \
  --hardware-discovery false --i2c-yubihsm /dev/i2c-1@0x24=/dev/gpiochip0:23
```

In another controller terminal, from `virtual-yubihsm`:

```sh
cargo run --release --locked -p yubihsm-qualification -- \
  connector http://127.0.0.1:12345 24000001 smoke
```

Smoke is read-only and needs no login password. Use the serial configured in
the target profile. For PKCS #11, set
`PKCS11RS_YUBIHSM_URLS=http://127.0.0.1:12345` for the client. Stop the
connector with Ctrl-C after testing.

## Profile-based service

Install the current supervisor following its
[build and installation recipe](https://github.com/qpernil/usb-gadget-supervisor#build).
Build the HSM source or use the checksummed ARM64 binary in
`prebuilt/aarch64/`. Set the profile command to the chosen executable.

```sh
cargo build --release --locked -p virtual-yubihsm-i2c
cp profiles/virtual-yubihsm-i2c.toml /tmp/virtual-yubihsm-i2c.toml
editor /tmp/virtual-yubihsm-i2c.toml
sudo install -o root -g root -m 0644 /tmp/virtual-yubihsm-i2c.toml \
  /opt/usb-gadget-supervisor/profiles/virtual-yubihsm-i2c.toml
```

Set `worker.command` to the absolute path of the built HSM. The supplied
[profile](../profiles/virtual-yubihsm-i2c.toml) uses the existing `per` account,
serial `24000001`, and state under `/var/lib/virtual-yubihsm-i2c`. Adjust the
account if needed. No new service account or device group is required.
The supervisor creates private directories and passes the device declared as
`fd = 3`; the HSM receives no supplementary groups. Add `--persistence`,
`immediate` to the profile's arguments for immediate durable writes.

The same native driver launcher can manage module and overlay lifetime for
the permanent service. Build `target-driver` and the kernel artifacts as in
the manual recipe, then create an instance override:

```sh
sudo systemctl edit usb-gadget-supervisor@virtual-yubihsm-i2c.service
```

Use absolute paths to the driver checkout on this machine:

```ini
[Service]
ExecStart=
ExecStart=/absolute/path/to/raspberry-pi-i2c-target/target/release/target-driver --profile virtual-yubihsm-i2c --ready-gpio 17 0x24 /absolute/path/to/raspberry-pi-i2c-target/kernel
```

```sh
sudo systemctl enable --now usb-gadget-supervisor@virtual-yubihsm-i2c.service
```

The existing unit's `KillMode=mixed` lets the launcher forward stop to the
supervisor, wait for it, and unload the driver. Its SIGHUP reload is forwarded
to the supervisor, which reloads the root-owned profile. Rebuild the module
after kernel upgrades. No privileged shell hooks or separate boot-loading
script are required. Stop the service before a foreground bench run.

When the kernel driver is already managed separately, the profile can also be
launched directly:

```sh
sudo /opt/usb-gadget-supervisor/usb-gadget-supervisor --profile virtual-yubihsm-i2c
```

## Service installation

The following alternative directly launches the HSM using a dedicated account
and a udev rule. The profile-based recipe above uses the existing account and
inherited FD 3 instead.

Arrange for a separate privileged boot task to load the device-tree overlay
and the kernel module before starting the direct-launch service. The native
profile-based launcher above manages this lifetime automatically. The supplied
service waits for `/dev/bsc-target0`; it does not install or load either artifact.
Rebuild the module against the running kernel after kernel upgrades. The protocol
service itself needs only read/write access to `/dev/bsc-target0` and exclusive
access to its state directory. It does not configure the overlay, module,
target address, or READY GPIO.

The supplied udev rule grants the character device to a dedicated
`virtual-yubihsm` group. The systemd unit runs with no capabilities, denies all
IP networking, and gives its service identity a private state directory with
mode `0700`. The CBOR state files contain private key material and are always
written with mode `0600` using an atomic, synced replacement. Mutations are
batched for at most 500 ms by default, coalescing a burst of commands into one
replacement. Graceful shutdown flushes pending state. Use
`--persistence immediate` when a successful mutating response must wait for its
own durable write. A sidecar lock prevents concurrent service instances.
Corrupt or wrong-serial state fails closed rather than causing an implicit
factory reset.

An example installation, after installing the driver and its overlay, is:

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin virtual-yubihsm
sudo install -o root -g root -m 0755 prebuilt/aarch64/virtual-yubihsm-i2c \
  /usr/local/sbin/virtual-yubihsm-i2c
sudo install -o root -g root -m 0644 deploy/90-virtual-yubihsm-i2c.rules \
  /etc/udev/rules.d/90-virtual-yubihsm-i2c.rules
sudo install -o root -g root -m 0644 deploy/virtual-yubihsm-i2c.service \
  /etc/systemd/system/virtual-yubihsm-i2c.service
printf 'YUBIHSM_SERIAL=12345678\nYUBIHSM_PERSISTENCE=batched\n' | \
  sudo tee /etc/virtual-yubihsm-i2c >/dev/null
sudo chmod 0600 /etc/virtual-yubihsm-i2c
sudo udevadm control --reload
sudo udevadm trigger /dev/bsc-target0
sudo systemctl daemon-reload
sudo systemctl enable --now virtual-yubihsm-i2c.service
```

The controller can also run persistently using the connector's
[systemd recipe](https://github.com/qpernil/pkcs11rs/blob/master/docs/connector.md#running-as-a-systemd-service),
with `experimental-i2c` enabled and the configured endpoint in `ExecStart`.

The target can then run with no configured network interface. Installing new
software is a separate administrative operation and can be performed before
network isolation or by replacing the SD-card image.

## Qualification through the connector

The Rust controller implementation lives entirely in `pkcs11rs-connector`.
Both the PKCS #11 module and `yubihsm-qualification` use its HTTP API; the
qualification tool does not open I2C or READY GPIO devices.

From the `pkcs11rs` checkout on a Linux controller, opt into the experimental
transport and serve a configured target:

```sh
cargo run --release -p pkcs11rs-connector --features experimental-i2c -- \
  --hardware-discovery false \
  --i2c-yubihsm /dev/i2c-1@0x24=/dev/gpiochip0:23
```

The connector registers the serial
returned by DeviceInfo. For a target reporting serial 24000001, run the
read-only profile from the `virtual-yubihsm` checkout:

```sh
cargo run -p yubihsm-qualification -- \
  connector http://127.0.0.1:12345 24000001 smoke
```

`managed` and `extensions` profiles use the same HTTP transport. Provide the
credential through the existing qualification environment variables; never
put an Authentication Key password in process arguments. The separate
`pkcs11rs/tools/i2c-stress.py` tool exercises raw bus framing, delayed
header/body reads, and READY directly for lab diagnostics.

## Hardware validation

The bench uses ubuntu4 as controller and two Pi 3B+ targets at `0x24` and
`0x25`, with READY inputs GPIO23 and GPIO22. Each target is profile-launched as
`per` with inherited FD 3 and separate qualification state. The ABI 3 handshake
requires coordinated updates; qualification must cover both authenticated
compatibility and simultaneous traffic during a slow command. See the driver
[hardware plan](https://github.com/qpernil/raspberry-pi-i2c-target/blob/main/docs/hardware-test-plan.md).

ABI 3 qualification passes all 31 supported vendor shell cases on each target,
with continuous peer echo traffic during cryptographic operations. Both targets
also pass 1,000 simultaneous raw exchanges with delayed reads and intentional
abandonment. A delayed worker-response probe confirms latest-request recovery
without changing the HSM's synchronous read/execute/write loop.

HTTP smoke, managed and extension qualification pass against both deployed targets.
