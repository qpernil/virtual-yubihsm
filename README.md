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
    |-- in-memory object store and implemented commands
    |-- durable encrypted device state (next step)
    |-- options and audit (planned)
    v
software-key-core (path dependency)
```

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
- EC and Ed25519 import/generation, public projection, ECDSA, EdDSA and ECDH
  through the path-dependent `software-key-core` crate;
- HMAC SHA-1/SHA-256/SHA-384/SHA-512 import/generation/sign/verify.

Still to implement before claiming device compatibility: RSA, AES and wrap
commands, templates, OTP AEAD, device options and audit log, durable encrypted
state, and the final FunctionFS worker adapter. Unsupported commands return the
documented `INVALID COMMAND` response rather than pretending to succeed.

## Persistence checkpoint and next step

Persistence is intentionally in memory for the current checkpoint. A `Device`
owns its objects for the lifetime of that instance: closing or expiring a
secure session does not remove them, but dropping the device or restarting the
process does. `ResetDevice` clears the in-memory objects and sessions and then
reinstalls the factory Authentication Key. The device static P-256 identity is
also regenerated when a new factory-default device is constructed unless an
explicit deterministic key is supplied for a test fixture.

The next persistence step is a versioned, encrypted image of the complete
device state. It will contain the device identity, objects, sequence metadata,
options and audit state, while secure sessions and message counters remain
volatile. Mutating commands must publish the new image atomically before
returning success and must leave the previous state intact if storage fails.
The encryption key will be supplied from outside the image so an Authentication
Key is never required to decrypt the state which contains that same key.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The factory Authentication Key is object ID 1, all capabilities, all delegated
capabilities and all domains. Its compatibility password is `password`; change
or delete it before connecting the core to any persistent deployment.
