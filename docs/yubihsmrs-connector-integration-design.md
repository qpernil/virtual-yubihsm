# Built-in Virtual YubiHSM for `yubihsmrs-connector`

## Status

This document records a design only. It does not change either runtime.

The intended result is a Virtual YubiHSM hosted directly inside the
`yubihsmrs-connector` process. The connector calls a Rust library API; it does
not reach the virtual device through USB, HTTP, a Unix socket, or a worker
subprocess.

## Objective

One protocol implementation must serve two transport frontends:

```text
USB host                                      connector client
   |                                                |
FunctionFS                              yubihsmrs-connector protocol
   |                                                |
virtual-yubihsm-worker                  built-in virtual-device backend
   |                                                |
   +--------------- virtual-yubihsm-core -----------+
                            |
                  objects, sessions and state
```

The USB worker remains the deployable USB-gadget frontend. The connector gains
a built-in backend whose request path calls `virtual-yubihsm-core` directly.
To a connector client, a built-in instance behaves like an ordinary YubiHSM
selected through the connector's existing public API.

## Existing foundation

The repository already contains `crates/virtual-yubihsm-core`, a Rust library
crate independent of FunctionFS and HTTP. Its `Device` type currently provides
the essential embedding surface:

- `Device::factory_default` and `Device::from_persistent_state` construct a
  device;
- `Device::handle_encoded` accepts and returns complete native YubiHSM frames;
- `Device::take_persistent_change` identifies a successful durable mutation and
  advances the state epoch;
- `Device::persistent_state` produces the version-1 CBOR image;
- `Device::clear_sessions` drops transport-local volatile sessions.

The main work is therefore not a second Virtual YubiHSM implementation. It is
to make this existing library a stable cross-repository dependency and add a
small `yubihsmrs-connector` backend around it.

## Crate boundaries

### `virtual-yubihsm-core`

The core owns:

- native frame parsing and response encoding;
- secure sessions and session counters;
- objects, authorization, domains and delegated capabilities;
- the global numeric-object-ID generation mapping;
- options, audit state and the 64-bit persisted state epoch;
- factory bootstrap, trusted fixture provisioning and state restoration; and
- serialization and validation of the schema-1 persistent image.

It must not acquire dependencies on:

- HTTP or a particular connector protocol;
- FunctionFS or USB gadget descriptors;
- Tokio or another caller-selected asynchronous runtime;
- displays, GPIO or supervisor control channels; or
- connector device discovery.

The core remains single-owner and synchronous. Its command method takes
`&mut self`; each frontend is responsible for synchronization and scheduling.

### `virtual-yubihsm-worker`

The worker continues to own:

- the `usb-gadget-supervisor` control protocol;
- FunctionFS endpoint lifecycle and USB identity;
- display, buttons and activity indication; and
- conversion between USB transfers and core command calls.

It contains no independent YubiHSM command implementation.

### `yubihsmrs-connector`

The connector owns:

- connector configuration and client-facing APIs;
- physical-device discovery and USB access;
- built-in virtual-device registration and selection;
- per-device admission, command serialization and timeouts; and
- process startup and graceful shutdown.

It treats the Virtual YubiHSM as another command backend. HTTP handlers must
not contain virtual-device-specific protocol behavior.

## Making the core a consumable Rust library

`virtual-yubihsm-core` should remain a normal library package with a public,
documented embedding API. A connector build should consume a pinned release or
Git revision rather than copy source files.

The current workspace-only dependency on the sibling `software-key-core` path
must be made reproducible outside the developer checkout. The preferred order
is:

1. publish or otherwise version `software-key-core` as an independently
   resolvable Rust package;
2. make `virtual-yubihsm-core` depend on that version;
3. let local workspaces override it with Cargo's patch mechanism when needed;
4. pin the `virtual-yubihsm-core` version or Git revision in
   `yubihsmrs-connector`.

`publish = false` may remain while a pinned Git dependency is used, but every
transitive dependency must still be resolvable from the Git checkout. A
published crate is preferable once the API is stable.

The connector-facing API should stay deliberately small. The existing API is
already close to the desired form:

```rust
use virtual_yubihsm_core::{Device, DeviceConfig};

let mut device = Device::from_persistent_state(config, &encoded_state)?;
let response: Vec<u8> = device.handle_encoded(&request);
```

No connector type should appear in the core API. If a higher-level facade is
added, it should only combine `Device` with the shared persistence coordinator;
it must not introduce transport concepts.

## Connector backend

The connector adds one adapter per configured virtual instance:

```rust
struct BuiltInVirtualYubiHsm {
    persistence: StatePersistenceHandle<Device>,
    identity: DeviceIdentity,
}
```

The exact mutex and persistence-handle types belong to the connector and the
shared persistence library. The persistence handle owns the synchronized
`Device`; the adapter must not keep a second copy. Conceptually, command
handling is:

1. acquire the instance's command lock;
2. call `Device::handle_encoded` with exactly one native request frame;
3. call `Device::take_persistent_change` while still holding the state lock;
4. when it reports a mutation, submit that state to the configured direct or
   batched persistence path;
5. wait for the persistence receipt required by that mode;
6. release the lock and return the encoded response.

This is the same ordering currently used by the FunctionFS worker. In
particular, the connector must not return a successful mutating response before
the shared persistence coordinator says that response may be released.

Each virtual instance has its own lock and persistence stream. Commands to one
instance are serialized because the YubiHSM session state is sequential;
different physical or virtual instances may execute concurrently.

## Persistence ownership

Both frontends must use the existing generic direct-or-batched storage
implementation. The connector must not create another atomic-file writer or a
second interpretation of batching.

If the generic persistence implementation remains exported from
`usb-gadget-worker`, `yubihsmrs-connector` can initially reuse it. A later
cleanup may extract it into a transport-neutral crate, but that extraction must
not change behavior or the state image.

For each built-in instance:

- the state file remains `STATE_DIRECTORY/yubihsm-<serial>.cbor`;
- a missing file causes an explicit factory bootstrap and creation of the
  initial image before the device is advertised;
- corrupt, unsupported or wrong-serial state fails closed;
- schema remains version 1;
- the state epoch and global ID-generation mapping are restored unchanged;
- sessions are never persisted;
- graceful shutdown flushes pending batched state; and
- a persistence failure withdraws or fails the instance rather than continuing
  with state that cannot meet its configured durability contract.

The connector must exclusively lock each state file or state directory for the
lifetime of the instance. The USB worker and connector may not open the same
persisted device simultaneously. Supporting two transports for one live device
would require a single state-owning process and is outside this design.

## Configuration

The connector should express built-in instances explicitly rather than infer
them from an empty USB inventory. A representative configuration is:

```toml
[[virtual_yubihsm]]
serial = "12345678"
state_directory = "/var/lib/yubihsmrs-connector/virtual-yubihsm-12345678"
persistence = "immediate"

[[virtual_yubihsm]]
serial = "87654321"
state_directory = "/var/lib/yubihsmrs-connector/virtual-yubihsm-87654321"
persistence = { batched = { maximum_delay_ms = 500 } }
```

Exact syntax should follow the connector's existing configuration model. The
required semantics are:

- every serial is explicit and unique across the connector's physical and
  virtual inventory;
- every state directory is explicit and unique;
- persistence defaults to the same batched policy as the USB worker unless
  configured otherwise;
- a duplicate serial or state path is a startup error; and
- a virtual instance is never silently substituted for an absent physical
  device.

If the connector exposes one selected device per listener, selecting a built-in
instance replaces the physical USB backend for that listener. If it exposes a
multi-device inventory, each built-in instance is registered beside physical
devices. This routing distinction does not affect the core integration.

## Identity and client behavior

The backend reports a stable identity derived from `DeviceConfig` and the
core's device-information response. The connector may mark the manufacturer or
transport description as virtual for administration, but it must not rewrite
YubiHSM command frames or invent different protocol behavior.

Existing clients should need only the connector address and normal device
selection. Authentication Keys, object sequences, audit behavior and command
errors must be identical between USB and built-in execution from the same
initial state.

## Lifecycle

Startup for each instance is:

1. validate configuration and uniqueness;
2. acquire exclusive state ownership;
3. restore schema-1 state or perform explicit factory bootstrap;
4. start the shared persistence coordinator;
5. register the backend as available; and
6. begin accepting commands.

Shutdown reverses that order:

1. stop admitting new commands;
2. drain the instance's current command;
3. flush and shut down persistence;
4. clear volatile sessions;
5. unregister the instance; and
6. release state ownership.

A connector process or built-in-backend restart reconstructs the device from
durable state and therefore clears sessions. Ordinary HTTP connection churn
does not clear them: secure sessions belong to the device protocol, not to one
HTTP connection, which matches a physical connector's behavior.

## Error handling

Protocol errors remain encoded by `virtual-yubihsm-core` as ordinary YubiHSM
responses. Connector/runtime errors remain outside the frame protocol:

- malformed complete frames are handled by the core;
- request truncation and connector body limits are connector errors;
- state restoration failure prevents registration;
- runtime persistence failure makes the instance unavailable; and
- a command with an uncertain outcome is never replayed automatically.

## Validation

The implementation is complete when the following pass:

1. The connector links `virtual-yubihsm-core` as a Rust dependency with no
   copied protocol code.
2. A factory built-in instance answers device information and authenticates
   through an ordinary connector client.
3. The same protocol fixture produces byte-identical responses through the
   direct core call, FunctionFS adapter and connector adapter.
4. Immediate and batched mutation tests use the shared persistence coordinator
   and enforce response-release ordering.
5. Restart restores objects, global ID generations and state epoch while
   clearing sessions.
6. Corrupt state, duplicate serials, duplicate state paths and concurrent state
   ownership all fail closed.
7. Two virtual instances and physical devices can serve concurrently without a
   global command lock.
8. Existing Virtual YubiHSM core, worker and persistence tests continue to pass
   without schema changes.

## Implementation order

1. Make `software-key-core` and `virtual-yubihsm-core` reproducible
   cross-repository dependencies.
2. Stabilize and document the small core embedding API without changing
   protocol behavior.
3. Add the connector configuration and built-in backend adapter.
4. Reuse the shared persistence coordinator and add exclusive state ownership.
5. Add lifecycle, concurrency and failure-path integration tests.
6. Qualify the built-in backend with the same YubiHSM Auth and persistence
   scenarios already used for the USB worker.
