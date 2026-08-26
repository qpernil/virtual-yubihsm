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

The proposed direct, in-process integration of this core as a built-in device
inside `yubihsmrs-connector` is specified in the
[built-in connector design](docs/yubihsmrs-connector-integration-design.md).
The virtual `derive-ecdh-kdf` command and its proposed
`CKM_PKCS11RS_PREFIXED_ECDH_DERIVE` mapping are specified in the
[prefixed ECDH derivation design](docs/prefixed-ecdh-derive.md).

An authenticated session receives exactly the Authentication Key object's:

- capabilities — operations that the session may request;
- delegated capabilities — the maximum capabilities that objects created or
  imported by the session may receive; and
- domains — the maximum domain set for newly created objects and the domain
  intersection used to find existing objects.

Using an existing object requires the command capability on the session, the
operation capability on the object, and at least one shared domain. Creating an
object additionally requires all requested domains and capabilities to be
within the session's domain and delegated-capability ceilings. Deletion is the
exception: it requires the type-specific delete capability on the session and a
shared domain, but does not require the target object to authorize its own
deletion.

## Supported protocol

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
- atomic prefixed ECDH plus mandatory X9.63 derivation under a separate
  `derive-ecdh-kdf` capability, allowing a static authentication key to derive
  session-specific material without exposing its reusable raw ECDH secret;
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
- native display images for either the 240x240 ST7789 color panel or the
  128x64 SH1106 one-bit OLED, with a strap-hole LED driven by the shared
  `display-backends::indicator` scheduler: stopped with the LED off while USB is
  inactive, a 0.333 Hz three-second cycle while idle, and a measured 100 ms
  fast cycle throughout command execution with 67 ms on and 33 ms off.
  Authenticated `Blink Device` requests extend the fast cadence for their
  requested duration.

All officially registered cryptographic algorithms are represented and
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
Before reading or creating that image, the worker exclusively locks the
persistent sidecar `STATE_DIRECTORY/yubihsm-<serial>.lock` and retains the lock
through its final persistence flush. The sidecar remains present when unlocked;
the kernel lock, rather than file existence, records ownership. A concurrent
owner is a startup error.

The CBOR image is deliberately not encrypted. It contains private key material
and Authentication Keys, so `STATE_DIRECTORY` is part of the trusted boundary
and must only be accessible to the worker identity and the administrator.
Secure sessions and secure-message counters are never serialized. `ResetDevice`
clears objects, options, audit state and sessions, then reinstalls the factory
Authentication Key and generates a new static P-256 device identity.

Persistent state retains the latest generation for every numeric object ID seen
since the last device reset, including deleted objects. The mapping is shared
by every object type: creation, including recreation after deletion, successful
in-place opaque replacement, and Authentication Key changes advance the ID's
counter. Read-only object use and deletion do not affect the generation. Object
information and listings expose the generation's low byte as the protocol
sequence. A never-before-seen ID starts at generation zero. Trusted fixture
provisioning instead preserves its explicitly supplied sequence.

Every durable transaction recorded by the worker also advances a persisted
64-bit state epoch. The epoch survives restart and `ResetDevice`. Batched
storage may omit intermediate images, but every stored snapshot still carries
an ordering key that can support retained history later.

The asymmetric YubiHSM Auth persistence path has also been exercised against a
physical YubiKey. See the
[advanced YubiHSM Auth qualification record](docs/advanced-yubihsm-auth-qualification.md).

## Compatibility behavior

The reported object capacity follows the physical device's nominal 256-object
limit. Once that many objects exist, `Get Storage Info` reports zero free object
slots, but the virtual device continues to permit additional objects.

Force-audit mode rejects ordinary authenticated commands when the audit log is
full; it does not implicitly enable auditing for every command. `Create Session`
and `Authenticate Session` may be configured for audit, but are never rejected
because the log is full, avoiding an authentication deadlock. Successful
authentication that cannot be logged is reflected in the unlogged-authentication
counter. The `Session Message` envelope itself can never be audited; its
decrypted command is considered separately.

Successful command responses must fit the protocol's maximum encrypted return
frame. An otherwise successful operation that produces too much return data is
reported as `WRONG LENGTH`. `Reset Device` also renews the static P-256 device
identity in addition to restoring the factory object and option state.

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

The display uses the device-neutral `display-backends::indicator` scheduler and
a worker-supplied renderer that maps its one logical bit to the appropriate
complete color or monochrome image. Its selected cadence is a direct
consequence of the current USB and command state:

| State | Display and LED behavior |
| --- | --- |
| No USB personality | Power the complete display off. |
| Personality present, but USB suspended or unbound | Keep the YubiHSM image visible, stop the periodic scheduler, and force the LED off. |
| USB bound and awake, with no command running | Invert every 1.5 seconds: a symmetric three-second, 0.333 Hz idle cycle. |
| A command is running | Use the measured 100 ms fast cycle: hold on for 67 ms and off for 33 ms. |
| An authenticated `Blink Device` duration remains | Continue using the same fast cycle after returning the command response. |

Command activity starts an LED edge. The next fast delay follows the resulting
state: 67 ms after an on edge and 33 ms after an off edge. Fast activity takes
precedence over the slow idle cadence. Activity always establishes an on phase;
if slow idle is already on, an 8 ms off separator makes the following on edge
visible. A short command then finishes off, while a sustained command continues
directly into the 67/33 ms cadence. Periodic idle restarts from off afterward.
The stopped state always forces the LED off.

A monotonic command epoch preserves a command that starts and finishes during a
synchronous frame write. Activity arriving while a pulse is already visible may
retain one additional pulse; further activity coalesces rather than building a
delayed animation queue. Edges begin at least 8 ms apart, with renderer time
included in that interval rather than added to it. A slower display therefore
becomes the natural rate limit.

`Blink Device` is asynchronous from the caller's perspective: its response is
returned before the requested blinking ends. A small worker-side timer retains
the shared scheduler's scoped fast-cadence override for the requested duration.
A later successful request replaces the remaining deadline; durations are
neither stacked nor added.

When a protocol command fails, the worker writes a diagnostic to the service
journal containing the command name and byte, the returned device error, and,
for an authenticated command, its session and Authentication Key identifiers.
It never logs command payloads or cryptographic material. These diagnostics are
separate from the device audit log. The `Session Message` envelope itself is
never audited. Configured `Create Session` and `Authenticate Session` operations
can be audited, while decrypted commands are audited individually.

[`profiles/virtual-yubihsm.toml`](profiles/virtual-yubihsm.toml) is the
installation template for the 240x240 ST7789 color display;
[`profiles/virtual-yubihsm-sh1106-spi.toml`](profiles/virtual-yubihsm-sh1106-spi.toml)
selects the 128x64 SH1106 monochrome OLED. Replace the worker command and
account in the chosen profile with deployment-specific absolute values. The
worker includes both native asset sets and selects one with `--display`; it
performs no image conversion at runtime. The profiles' named display and KEY3
resources intentionally match the corresponding `virtual-yubikey` profiles so
either worker can use the same wiring.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The factory Authentication Key is object ID 1, all capabilities, all delegated
capabilities and all domains. Its compatibility password is `password`; change
or delete it before connecting the core to any persistent deployment.
