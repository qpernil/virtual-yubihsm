# virtual-yubihsm

`virtual-yubihsm` is a software implementation of the YubiHSM 2 device
protocol. The protocol/device core is deliberately independent of USB,
FunctionFS, HTTP connector, and process-supervision concerns.

## Architecture

```text
host connector
    |
    | YubiHSM frames
    v
transport adapter (FunctionFS / HTTP / tests)
    |
    v
virtual-yubihsm-core
    |-- SCP03-style symmetric authentication
    |-- SCP11-style P-256 authentication
    |-- shared SCP03-style secure message channel
    |-- session authorization snapshot
    |-- object store, options, and chained audit log
    |-- versioned durable CBOR state (sessions stay volatile)
    v
software-key-core (path dependency)
```

`software-key-core` owns reusable software keys and cryptographic
computations: asymmetric generation/signing/agreement, RSA encodings,
AES/CMAC/CCM/KWP, SCP03-style primitives, X9.63 derivation, and the Yubico
password KDF. `virtual-yubihsm-core` owns command decoding, capabilities,
delegated capabilities, domains, object lifecycle and persistence, sessions,
counters, audit policy, and device error mapping. This keeps the cryptography
shared without making either the HSM protocol or its authorization model a
dependency of other consumers.

An authenticated session receives exactly the Authentication Key object's:

- capabilities — operations that the session may request;
- delegated capabilities — the maximum capabilities that objects created or
  imported by the session may receive; and
- domains — the maximum domain set for newly created objects and the domain
  intersection used to find existing objects.

Using an existing object requires the command capability on the session, the
operation capability on the object, and at least one shared domain. Creating an
object additionally requires all requested domains and capabilities to be
within the session's domain and delegated-capability ceilings.

## Implemented checkpoint

- wire frame parsing and documented device errors;
- device information, storage information, pseudo-random, reset, close and
  session management;
- symmetric SCP03-compatible handshake and encrypted message exchange;
- asymmetric P-256 ECDH authentication with receipt and the common encrypted
  message exchange;
- capability, delegated-capability and domain authorization;
- Authentication Key create/change and Opaque object lifecycle;
- list/get-info/delete object behavior with cross-domain hiding;
- RSA-2048/3072/4096 import and generation, public projection, PKCS #1 v1.5
  and PSS signing, and PKCS #1 v1.5 and OAEP decryption;
- P-224/P-256/P-384/P-521, secp256k1, Brainpool P-256/P-384/P-512 and
  Ed25519 import/generation, public projection, ECDSA, EdDSA and raw ECDH;
- X25519 key import/generation, public projection and contributory key
  agreement as the first virtual extension algorithm;
- HMAC SHA-1/SHA-256/SHA-384/SHA-512 import/generation/sign/verify;
- AES-128/192/256 symmetric keys and ECB/CBC commands;
- AES-CCM wrap keys, authenticated arbitrary-data wrapping, policy-preserving
  wrapped-object export/import, RSA-OAEP plus AES-KWP hybrid wrapping, and the
  PKCS#8 key-only RSA wrap/import format;
- Yubico OTP AES-128/192/256 AEAD keys, credential creation/randomization,
  rewrapping and OTP decryption with private-ID and CRC validation;
- generated-key attestation certificates signed by the built-in P-256 device
  identity or a domain-authorized P-256 attestation key;
- force-audit, per-command audit, algorithm-toggle and FIPS-mode options,
  chained log entries and log-index reclamation;
- versioned CBOR persistence of objects, device identity, sequence metadata,
  options and audit state, with sessions and message counters kept volatile;
- a complete unprivileged `usb-gadget-supervisor` worker exposing the official
  `1050:0030` full-speed bulk endpoint pair over FunctionFS, with the configured
  device serial published as the USB serial-number string descriptor and the
  physical YubiHSM 2 Microsoft OS 1.0 declaration (`MSFT100`, vendor request
  `0x27`, interface 0 compatible ID `WINUSB`);
- a native ST7789 YubiHSM display with a green strap-hole LED and one
  invert-only blink scheduler: stopped with the LED off while USB is inactive,
  a 0.333 Hz three-second cycle while idle, and a measured 100 ms fast cycle
  throughout command execution with 67 ms on and 33 ms off. Command entry and
  exit each add an immediate inversion; authenticated `Blink Device` requests
  extend the fast cadence for their requested duration.

All officially registered cryptographic algorithms are now represented and
their general-purpose cryptographic command families are implemented. SSH
certificate signing is intentionally out of scope; template storage remains
available for protocol compatibility, while `Sign SSH Certificate` returns the
documented `INVALID COMMAND` response. The wrapped-object plaintext
representation is versioned for virtual-device round-trips; interoperability
fixtures from physical YubiHSM exports remain a separate validation step.

## Persistence

The worker follows the same storage pattern as `virtual-yubikey`. It reads and
writes `STATE_DIRECTORY/yubihsm-<serial>.cbor`, creates the initial image before
serving USB, and atomically replaces it after persistent changes. Temporary and
final files are created with mode `0600`, synced before replacement, and the
containing directory is synced after replacement. A corrupt, unsupported, or
wrong-serial image fails closed rather than silently factory-resetting.

The CBOR image is deliberately not encrypted. It contains private key material
and Authentication Keys, so `STATE_DIRECTORY` is part of the trusted boundary
and must only be accessible to the worker identity and the administrator.
Secure sessions and secure-message counters are never serialized. `ResetDevice`
clears objects, options, audit state and sessions, then reinstalls the factory
Authentication Key while retaining the device's static identity.

## Worker lifecycle

`virtual-yubihsm-worker` is the project worker, not a second adapter process.
It receives the supervisor control channel on file descriptor 3, publishes its
USB personality, receives the FunctionFS bulk endpoint descriptors, and passes
each complete YubiHSM transfer to `virtual-yubihsm-core`. It clears volatile
sessions on bind, unbind and disable events, stalls unsupported control
requests, and participates in the supervisor's quiesce handshake. The
supervisor turns the worker's Microsoft OS declaration into the special string
descriptor and compatible-ID vendor response that make Windows bind WinUSB
without a separate INF. The display
power state follows the published USB personality rather than any particular
button. KEY3 uses the same detach/reinsert lifecycle as `virtual-yubikey`, so
ejecting is one way to publish no personality and reinsertion restores it.
KEY3 is tracked as a current logical level rather than a queue of edges: the
worker samples its initial active-low GPIO value, coalesces notifications, and
always converges USB presence to the latest physical state. A dropped wake can
therefore never strand the worker in the ejected state.

The bulk endpoint thread starts only after the supervisor reports `Enable`.
If FunctionFS cancels I/O on disable or unbind, the thread parks until a newer
endpoint activation arrives. Quiescence wakes it to exit, so the worker never
re-enters a disabled endpoint while the supervisor is waiting for
`Quiesced`.
Worker shutdown also powers the display off. The worker refuses to run as root.

### Display and blink lifecycle

The display uses one periodic invert-only scheduler. Its selected cadence is a
direct consequence of the current USB and command state:

| State | Display and LED behavior |
| --- | --- |
| No USB personality | Power the complete display off. |
| Personality present, but USB suspended or unbound | Keep the YubiHSM image visible, stop the periodic scheduler, and force the LED off. |
| USB bound and awake, with no command running | Invert every 1.5 seconds: a symmetric three-second, 0.333 Hz idle cycle. |
| A command is running | Use the measured 100 ms fast cycle: hold on for 67 ms and off for 33 ms. |
| An authenticated `Blink Device` duration remains | Continue using the same fast cycle after returning the command response. |

Entering and leaving command activity each add one immediate LED inversion and
restart the selected periodic timer from that edge. The next fast delay follows
the resulting state: 67 ms after an on edge and 33 ms after an off edge. Fast
activity takes precedence over the slow idle cadence. Every periodic event is
an inversion; the stopped state is the sole exception and always forces the LED
off.

Activity notifications carry current state rather than a history of start/end
events. Multiple transitions can therefore be coalesced while the synchronous
ST7789 frame writer is busy, preventing completed command bursts from producing
delayed blinking. Overlapping command guards keep the fast cadence selected
until the last guard exits.

`Blink Device` is asynchronous from the caller's perspective: its response is
returned before the requested blinking ends. A later successful `Blink Device`
request replaces the remaining deadline with its duration measured from the
new command; durations are neither stacked nor added.

When a protocol command fails, the worker writes a diagnostic to the service
journal containing the command name and byte, the returned device error, and,
for an authenticated command, its session and Authentication Key identifiers.
It never logs command payloads or cryptographic material. These diagnostics are
separate from the device audit log and do not change the rule that meta-commands
are never audited.

[`profiles/virtual-yubihsm.toml`](profiles/virtual-yubihsm.toml) is an
installation template for the supervisor. Replace the worker command and
account with deployment-specific absolute values. Its named display and KEY3
resources intentionally match the `virtual-yubikey` profile so either worker
can use the same display HAT wiring.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The factory Authentication Key is object ID 1, all capabilities, all delegated
capabilities and all domains. Its compatibility password is `password`; change
or delete it before connecting the core to any persistent deployment.
