# YubiHSM qualification

`yubihsm-qualification` is the common behavioral test boundary for the virtual
device and reference hardware. A scenario sends and receives complete encoded
YubiHSM frames through `FrameTransport`; it does not call decrypted command
handlers or inspect device objects. The secure-session client independently
constructs and verifies the SCP03-compatible wire exchange using the shared,
protocol-neutral crypto primitives from `software-key-core`.

## Target matrix

| Target | Adapter | What it qualifies |
| --- | --- | --- |
| Fresh `virtual-yubihsm-core` | `InProcessTransport` | Protocol core, sessions, authorization, objects, audit semantics. |
| Connector-hosted virtual HSM | `ConnectorHttpTransport` | Core plus actor, registry, persistence boundary, and HTTP command route. |
| USB-gadget virtual HSM | `ConnectorHttpTransport` through a connector that claimed the gadget | FunctionFS framing, USB lifecycle, connector USB transport, and the core. |
| Physical YubiHSM | `ConnectorHttpTransport` through a connector that claimed the HSM | Reference behavior over the same public command path. |

The last three deliberately share one adapter. Their difference is the device
claimed by the connector, not the frame contract. Connector status should be
recorded beside a qualification run so an embedded target (`kind: embedded`)
cannot be mistaken for a USB target (`kind: usb`). For USB targets, record the
physical setup separately: a virtual gadget and a real HSM intentionally have
the same transport kind.

## Profiles

`smoke` is read-only and needs no Authentication Key. It checks malformed and
unknown frame errors, plain Echo, device identity, the device authentication
public key, and rejection of a session-only command sent in the clear. This is
the default connector profile and is safe when the target's provisioning is
unknown.

`managed` opens an SCP03-compatible session and requires an Authentication Key
with the capabilities used by the scenarios. It checks encrypted commands,
temporary opaque-object lifecycle, and the complete Authentication Key policy:

- session capabilities authorize commands;
- delegated capabilities are the maximum capabilities of newly created
  objects; and
- session domains are the maximum domains of newly created objects.

It chooses unused IDs in the `0x7e00` range and deletes every successfully
created object. It does not reset the device or change options. A failed or
interrupted run can leave temporary objects behind, so use it only on a managed
qualification target.

The managed crypto scenarios additionally cover:

- the FIPS-197 AES-128, AES-192, and AES-256 ECB known-answer vectors, plus CBC
  encrypt/decrypt round trips;
- the RFC 4231 HMAC-SHA-256 known answer, positive verification, and tamper
  rejection;
- authenticated `Wrap Data`/`Unwrap Data` and wrapped-object export/delete/
  import recovery;
- RSA-AES object export/import and PKCS #8 key-material recovery through public
  and private RSA wrap keys;
- generation, public-key encoding, DER-signature decoding, and independent
  verification for every official Weierstrass curve;
- RSA-2048 PKCS #1 and PSS signatures, PKCS #1 decryption, and OAEP decryption;
- Ed25519 signing and two-party P-256 ECDH agreement;
- the official Yubico OTP credential vector, AEAD creation, decryption, and
  randomization;
- attestation-certificate DER parsing and binding to the generated target key;
- asymmetric P-256 session authentication, receipt verification, and the
  authorization snapshot retained by an established session;
- non-mutating reads of every standard option and rejection of invalid options;
  and
- a negative matrix for malformed authenticated commands.

Expected signatures and shared secrets are verified by the independent client
side using public keys returned over the protocol. AES and HMAC use fixed
published vectors rather than values produced by the device implementation.

`extensions` adds X25519 agreement against an independently implemented peer
and prefixed ECDH with an independently calculated X9.63 KDF result. It includes
the complete `managed` profile first, but keeps additions outside the standard
command set visibly separate.

`ephemeral` adds persistent audit configuration and audit-log assertions. It
proves that Create Session and Authenticate Session can be audited while the
Session Message meta-command cannot. Because audit entries cannot be removed
without also advancing the device log index, the command-line runner only
allows this profile on a fresh in-process core. Future destructive hardware
profiles must remain explicit and must never silently reset a device.

## Running

The complete fresh-core profile uses factory Authentication Key 1 and its
factory password:

```sh
cargo run -p yubihsm-qualification -- core
```

Run read-only checks against any connector target:

```sh
cargo run -p yubihsm-qualification -- \
  connector http://127.0.0.1:12345 12345678 smoke
```

For a dedicated target whose symmetric Authentication Key is derived from a
password, keep the password out of the process arguments:

```sh
YUBIHSM_QUALIFICATION_PASSWORD='password' \
YUBIHSM_QUALIFICATION_AUTH_KEY_ID=1 \
cargo run -p yubihsm-qualification -- \
  connector http://127.0.0.1:12345 12345678 managed
```

Use `extensions` instead of `managed` to include the additional command and
algorithm checks.

The current HTTP adapter intentionally accepts only plain `http://`. Run it on
loopback or a private test network. TLS and mutual-TLS policy are connector
tests, while this suite qualifies the YubiHSM frame behavior behind the HTTP
boundary.

## Adding scenarios

Each expectation belongs in the common runner unless it is inherently tied to
a transport lifecycle. Build requests from public protocol fields, send them
through `FrameTransport`, and validate only public response frames. Do not use
`Device::execute_inner`, object accessors, or device-side session code as an
oracle: doing so could make the test reproduce the implementation bug it is
meant to find.

Transport lifecycle tests wrap the same scenarios rather than copying them.
For example, a USB disconnect test should interrupt a normal command exchange,
wait for the connector to rediscover the target, and then rerun the common
read-only or managed scenario set.

X25519 and the prefixed-ECDH KDF command belong to the explicit extension
profile. Target observations should be captured as explicit expected data or a
narrowly documented target exception, never as a branch in the virtual
implementation itself.

## Ownership of tests

Public wire behavior belongs here so the same assertion can run through every
transport. Once an equivalent qualification scenario is established, the old
device-side wire test is removed. Unit tests in `virtual-yubihsm-core` remain
for internal invariants such as authorization helper behavior, global object
generation history, persistence migrations, canonical wrapped-object CBOR,
key-material promotion, and size limits that cannot be observed precisely from
the public protocol.
