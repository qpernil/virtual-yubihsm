# Built-in Virtual YubiHSM for `pkcs11rs-connector`

## Current architecture

`pkcs11rs-connector` can host one or more Virtual YubiHSM instances directly in
the connector process. The connector calls `virtual-yubihsm-core` through its
Rust API; embedded devices do not pass through USB, HTTP, a Unix socket, or a
worker subprocess internally.

One protocol implementation and one persistent runtime serve every deployed
frontend:

```text
USB host                 I2C controller              connector client
   |                           |                            |
FunctionFS                 BSC target            pkcs11rs-connector protocol
   |                           |                            |
USB worker                 I2C worker              embedded actor
   |                           |                            |
   +---------------------------+----------------------------+
                               |
              virtual-yubihsm-core persistent-runtime
                               |
                  device, sessions and durable state
```

The USB worker remains the deployable USB-gadget frontend. An embedded instance
behaves like an ordinary YubiHSM selected through the connector's public API.

## Crate boundaries

### `virtual-yubihsm-core`

The core owns:

- native frame parsing and response encoding;
- secure sessions and session counters;
- objects, authorization, domains and delegated capabilities;
- the global numeric-object-ID generation mapping;
- options, audit state and the persisted state epoch;
- factory bootstrap, fixture provisioning and state restoration;
- serialization and validation of the versioned persistent image.

On Unix, the optional `persistent-runtime` feature makes the core own:

- exclusive state-file locking from before restore through final flush;
- restore-or-create behavior and canonical state filenames;
- immediate or batched atomic persistence;
- serialized frame execution and durable mutation accounting; and
- transport-lifecycle session clearing.

The in-memory embedding surface consists primarily of:

- `Device::factory_default` and `Device::from_persistent_state`;
- `Device::handle_encoded` for complete native request and response frames;
- `Device::take_persistent_change` for successful durable mutations;
- `Device::persistent_state`, which writes version-3 state and restores
  version-1, version-2, and version-3 images; and
- `Device::clear_sessions` for transport-local volatile state.

Deployed frontends instead use `PersistentDevice` and its cloneable
`PersistentDeviceHandle`. `PersistentDevice::open` acquires durable ownership;
`PersistentDeviceHandle::execute` performs one complete frame with persistence
ordering; `clear_sessions`, `flush`, and `shutdown` define the remaining
lifecycle transitions.

The device core remains synchronous and single-owner. The optional persistent
runtime adds its persistence thread but contains no HTTP, FunctionFS, I2C,
Tokio, display, GPIO, or connector-discovery types.

### `virtual-yubihsm-worker`

The worker owns:

- the `usb-gadget-supervisor` control protocol;
- FunctionFS endpoint lifecycle and USB identity;
- display, buttons and activity indication; and
- conversion between USB transfers and core command calls.

It contains no independent YubiHSM command implementation.

### `virtual-yubihsm-i2c`

The I2C binary owns the Linux BSC target descriptor, driver-ABI and READY
validation, request/response polling, and signal handling. It uses the same
`PersistentDevice` API as the other deployed frontends and contains no
independent device or persistence implementation.

### `pkcs11rs-connector`

The connector owns:

- connector configuration and client-facing APIs;
- physical-device discovery and USB access;
- embedded virtual-device registration and selection;
- per-device admission, command serialization and timeouts; and
- process startup and graceful shutdown.

HTTP handlers treat each Virtual YubiHSM as another command backend and contain
no virtual-device protocol implementation.

## Embedded actor

Each configured virtual instance has one dedicated blocking actor. The
asynchronous adapter sends a request through a capacity-one Tokio MPSC channel
and receives the result through a one-shot channel. Synchronous cryptography,
state locking, and file synchronization therefore run outside Tokio executor
threads.

Cancelling an HTTP request drops only its response receiver. The actor still
finishes and accounts for a command it has accepted, so a command with an
uncertain outcome is never replayed automatically.

For each request the actor:

1. asks `PersistentDeviceHandle::execute` to process one native frame;
2. receives the response after the shared runtime has accounted for any
   durable mutation and satisfied the configured persistence policy; and
3. returns the encoded response through the connector transport.

A successful mutating response is released only when the persistence
coordinator permits it. Commands to one device are serialized, while separate
physical and virtual devices can execute concurrently.

## Persistence and ownership

The `virtual-yubihsm-core/persistent-runtime` feature composes the generic
coordinator from `usb-gadget-worker` with the device state machine. The USB,
I2C, and embedded frontends all use this API. For each instance:

- the state file is `STATE_DIRECTORY/yubihsm-<serial>.cbor`;
- a missing file triggers explicit factory bootstrap before registration;
- corrupt, unsupported, or wrong-serial state fails closed;
- new images use version 3 and validated version-1/version-2 metadata is
  migrated during restore;
- the state epoch and global ID-generation mapping are preserved;
- sessions are never persisted;
- graceful shutdown flushes pending batched state; and
- persistence failure makes the instance unavailable.

The runtime acquires the shared `StateLock` on
`STATE_DIRECTORY/yubihsm-<serial>.lock` before reading or creating state and
retains it through the final flush. The stable sidecar is locked because the
CBOR file is atomically replaced. The USB worker, I2C target, and connector can
use the same device state across separate runs, but cannot own it
simultaneously.

## Configuration

Embedded devices are enabled on Unix by building `pkcs11rs-connector` with the
`embedded-virtual-yubihsm` feature. Instances and common persistence policy are
configured with:

```text
--virtual-yubihsm SERIAL=STATE_DIRECTORY
--virtual-yubihsm-persistence batched|immediate
--virtual-yubihsm-batch-delay-ms MILLISECONDS
--hardware-discovery true|false
```

`--virtual-yubihsm` is repeatable. Serials and absolute state directories must
be unique. Virtual instances are opt-in; physical discovery remains enabled by
default and can be disabled independently for a virtual-only connector.

The default batched policy coalesces mutations for at most 500 ms. Immediate
mode waits for durable storage before every successful mutating response.
Persistence policy and batch delay apply to every embedded instance in one
connector process.

A build without `embedded-virtual-yubihsm` accepts the virtual-device arguments,
logs that they are ignored, and retains physical discovery. This permits one
service configuration to be used with either connector build.

## Identity and lifecycle

The backend identity is derived from the running firmware's `DeviceConfig` and
the core device-info response. Restoring a durable state file preserves objects,
options, audit history, and device secrets while adopting the running build's
firmware version, algorithm set, capacity, and part number. This lets a software
upgrade expose new virtual firmware capabilities without resetting provisioned
objects. The configured serial must still match the persisted serial. Connector
clients use the normal device-selection and command APIs; authentication keys,
object sequences, audit behavior, and protocol errors are the same for USB and
embedded execution from the same initial state.

Startup validates unique configuration, acquires state ownership, restores or
bootstraps the device, starts persistence, registers the backend, and then
accepts commands. Shutdown stops admission, drains the current command, flushes
persistence, clears sessions, unregisters the backend, and releases state
ownership.

Process restart reconstructs durable device state and clears sessions. HTTP
connection churn does not clear sessions because sessions belong to the device
protocol rather than to one connection.

Protocol errors remain encoded as ordinary YubiHSM responses. Connector errors
cover request truncation and body limits, unavailable state, persistence
failure, and transport lifecycle failures.

## Operational invariants

The integration maintains these properties:

1. Every frontend links `virtual-yubihsm-core` without copied protocol or
   persistent-device lifecycle code.
2. Factory instances answer device information and authenticate through the
   ordinary connector client path.
3. Direct-core, FunctionFS, I2C, and connector adapters preserve the same frame
   behavior.
4. Immediate and batched mutations enforce response-release ordering.
5. Restart restores objects, global ID generations, and state epoch while
   clearing sessions.
6. Corrupt state, duplicate serials, duplicate state paths, and concurrent
   ownership fail closed.
7. Multiple virtual and physical devices operate without a global command lock.

The connector remains intended for trusted-network deployment unless its TLS,
client-authentication, and admission controls are configured for the exposure.
The repositories currently use coordinated sibling paths; independently
reproducible releases require versioned crates or pinned Git revisions.
