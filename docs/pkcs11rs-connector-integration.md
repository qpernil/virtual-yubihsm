# Built-in Virtual YubiHSM for `pkcs11rs-connector`

## Current architecture

`pkcs11rs-connector` can host one or more Virtual YubiHSM instances directly in
the connector process. The connector calls `virtual-yubihsm-core` through its
Rust API; embedded devices do not pass through USB, HTTP, a Unix socket, or a
worker subprocess internally.

One protocol implementation serves the USB and embedded frontends:

```text
USB host                                      connector client
   |                                                |
FunctionFS                              pkcs11rs-connector protocol
   |                                                |
virtual-yubihsm-worker                  embedded virtual-device actor
   |                                                |
   +--------------- virtual-yubihsm-core -----------+
                            |
                  objects, sessions and state
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
- factory bootstrap, fixture provisioning and state restoration; and
- serialization and validation of the versioned persistent image.

Its embedding surface consists primarily of:

- `Device::factory_default` and `Device::from_persistent_state`;
- `Device::handle_encoded` for complete native request and response frames;
- `Device::take_persistent_change` for successful durable mutations;
- `Device::persistent_state`, which writes version-3 state and restores
  version-1, version-2, and version-3 images; and
- `Device::clear_sessions` for transport-local volatile state.

The core remains synchronous and single-owner. It contains no HTTP, FunctionFS,
Tokio, display, GPIO, connector-discovery, or supervisor types.

### `virtual-yubihsm-worker`

The worker owns:

- the `usb-gadget-supervisor` control protocol;
- FunctionFS endpoint lifecycle and USB identity;
- display, buttons and activity indication; and
- conversion between USB transfers and core command calls.

It contains no independent YubiHSM command implementation.

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

1. acquires the instance command lock;
2. passes one complete native frame to `Device::handle_encoded`;
3. checks `Device::take_persistent_change` while retaining state ownership;
4. submits a mutation to the configured immediate or batched persistence path;
5. waits for the persistence receipt required by that mode; and
6. releases the lock and returns the encoded response.

A successful mutating response is released only when the persistence
coordinator permits it. Commands to one device are serialized, while separate
physical and virtual devices can execute concurrently.

## Persistence and ownership

The connector and FunctionFS worker use the same direct-or-batched persistence
coordinator from `usb-gadget-worker`. For each instance:

- the state file is `STATE_DIRECTORY/yubihsm-<serial>.cbor`;
- a missing file triggers explicit factory bootstrap before registration;
- corrupt, unsupported, or wrong-serial state fails closed;
- new images use version 3 and validated version-1/version-2 metadata is
  migrated during restore;
- the state epoch and global ID-generation mapping are preserved;
- sessions are never persisted;
- graceful shutdown flushes pending batched state; and
- persistence failure makes the instance unavailable.

Each frontend acquires the shared `StateLock` on
`STATE_DIRECTORY/yubihsm-<serial>.lock` before reading or creating state and
retains it through the final flush. The stable sidecar is locked because the
CBOR file is atomically replaced. The USB worker and connector can use the same
device state across separate runs, but cannot own it simultaneously.

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

The backend identity is derived from `DeviceConfig` and the core device-info
response. Connector clients use the normal device-selection and command APIs;
authentication keys, object sequences, audit behavior, and protocol errors are
the same for USB and embedded execution from the same initial state.

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

1. The connector links `virtual-yubihsm-core` without copied protocol code.
2. Factory instances answer device information and authenticate through the
   ordinary connector client path.
3. Direct-core, FunctionFS, and connector adapters preserve the same frame
   behavior.
4. Immediate and batched mutations enforce response-release ordering.
5. Restart restores objects, global ID generations, and state epoch while
   clearing sessions.
6. Corrupt state, duplicate serials, duplicate state paths, and concurrent
   ownership fail closed.
7. Multiple virtual and physical devices operate without a global command lock.

## Next steps

1. Qualify the embedded backend against the same real-client scenarios used for
   the USB worker and physical YubiHSMs.
2. Extend cancellation, shutdown, persistence-failure, and state-lock fault
   injection around the actor boundary.
3. Harden connector authentication, authorization, admission control, and
   deployment guidance before exposing it beyond a trusted network.
4. Replace coordinated sibling paths with versioned releases or pinned Git
   revisions when independently reproducible checkouts become a requirement.
