# Virtual extensions

The virtual YubiHSM implements the published YubiHSM 2 protocol and also adds
the narrowly scoped extensions below. These additions exist for software-token
use cases and interoperability experiments. They do not imply that a physical
YubiHSM implements the same values or command forms.

| Extension | Discovery | Wire operation | Authorization |
| --- | --- | --- | --- |
| Authentication Key public projection | Support is learned by attempting the operation | `GetPublicKey` with object type `AuthenticationKey` | The Authentication Key must be visible in the session domain |
| X25519 | algorithm 56 | Existing asymmetric-key generate/import/public-key/`DeriveEcdh` commands | Existing generate, put, get-public-key and ECDH capabilities |
| Atomic prefixed ECDH with X9.63 KDF | Capability `derive-ecdh-kdf` (`0x38`) on the active Authentication Key and source key | `DeriveEcdhKdf` (`0x0c`), described in [prefixed ECDH derivation](prefixed-ecdh-derive.md) | `derive-ecdh-kdf` on both the session and source key, plus normal domain visibility |
| Direct RSAES-PKCS1-v1_5 secret-key wrapping | Presence of RSA and any actual virtual key algorithm | `GetRsaWrappedKey` and `PutRsaWrappedKey` with their normally nonzero hybrid-wrap selector fields set to zero | Existing `export-wrapped`/`import-wrapped` permissions; the source key also needs `exportable-under-wrap`, and delegated-capability/domain rules remain in force |
| X448 | algorithm 57 | Existing asymmetric-key generate/import/public-key/`DeriveEcdh` commands | Existing generate, put, get-public-key and ECDH capabilities |
| Ed448 | algorithm 58 | Existing asymmetric-key generate/import/public-key/`SignEddsa` commands | Existing generate, put, get-public-key and EdDSA-sign capabilities |
| Protected volatile derivation objects | Capability `session-objects` (`0x39`) on the active Authentication Key | `SessionObject` (`0x0b`), one envelope containing generation, ECDH, composition, derivation, controlled reads, AES-CMAC verification, and deletion | `session-objects` on the authenticated session; persistent ECDH and AES sources additionally require their ordinary operation capability and domain visibility |
| ML-DSA and ML-KEM | ML-DSA algorithms 59–61 and ML-KEM algorithms 62–64 | Existing asymmetric-key generation, seed import, public-key and object commands; `SignMlDsa` (`0x0d`), `EncapsulateMlKem` (`0x0e`), and `DecapsulateMlKem` (`0x0f`) | Existing generate/put/delete permissions plus `sign-ml-dsa` (`0x3a`), `encapsulate-ml-kem` (`0x3b`), or `decapsulate-ml-kem` (`0x3c`) on both the session and private-key object |

## Command hierarchy

The wire protocol has two levels. The ordinary top-level registry contains the
published YubiHSM commands plus five virtual commands in the unused
`0x0b`–`0x0f` range:

| Code | Command | Role |
| --- | --- | --- |
| `0x0b` | `SessionObject` | Namespace for operations on volatile protected objects |
| `0x0c` | `DeriveEcdhKdf` | One-shot prefixed ECDH and X9.63 derivation |
| `0x0d` | `SignMlDsa` | ML-DSA signing |
| `0x0e` | `EncapsulateMlKem` | ML-KEM encapsulation |
| `0x0f` | `DecapsulateMlKem` | ML-KEM decapsulation |

There is no generic extension dispatcher and no command-code negotiation.
Clients learn algorithms through the algorithm list and authorization through
object capabilities. Unsupported top-level codes receive the ordinary invalid
command response.

`SessionObject` is the only nested namespace. Its first payload byte selects
the operation and the remainder uses that operation's own request format. It
is an explicit family of commands rather than a modifier that can be placed in
front of any ordinary command. Volatile handles, output policy, and atomic
object creation require different payloads and responses from persistent
objects.

A nested operation reuses an ordinary command number only when the action has
the same meaning: generate an asymmetric key (`0x46`), derive ECDH (`0x57`),
or delete an object (`0x58`). Session-only transforms use their own nested
values `0x01`–`0x07`. Future operations that produce or consume volatile
handles belong in this namespace; operations that return ordinary wire data
and have independent authorization remain top-level commands. Reusing a number
does not imply that the nested payload equals the ordinary command payload.

Capabilities follow the same boundary. `session-objects` authorizes entry to
the namespace, while a persistent source must also permit its ordinary
operation. ML-DSA signing, ML-KEM encapsulation, ML-KEM decapsulation, and
prefixed ECDH retain separate capabilities because they are independently
grantable sensitive operations.

## Firmware profiles

The compiled firmware profile defines what the virtual device itself exposes
over the YubiHSM protocol. It does not describe PKCS #11 mechanisms assembled
by a client module or software session objects held outside the device.
The complementary
[firmware and provider capability model](https://github.com/qpernil/pkcs11rs/blob/master/docs/yubihsm-capability-layers.md)
documents those separate layers.

There are three deployment profiles:

| Cargo feature | Algorithms and commands | Purpose |
| --- | --- | --- |
| `firmware-yubihsm2` | Algorithms 1–55 and the YubiHSM 2-compatible command surface | Exercise physical-device compatibility without virtual extension commands |
| `firmware-secure-channel` | Baseline plus `SessionObject` and `DeriveEcdhKdf` | Keep client-side SCP11 ephemeral keys and intermediate agreements inside the device |
| `firmware-full` | Secure-channel profile plus X25519, X448, Ed448, ML-DSA, ML-KEM, and direct RSA wrapping | Fully featured virtual deployments and interoperability experiments |

`firmware-full` is the default. Build either restricted profile explicitly:

```sh
cargo build --no-default-features --features firmware-yubihsm2
cargo build --no-default-features --features firmware-secure-channel
```

The USB worker, I2C frontend, qualification binary, core, and embedded
connector all forward these same profile names. A connector firmware feature
also enables its embedded persistent runtime.

Two core and connector features are reserved for tests:
`test-firmware-prefixed-ecdh` and `test-firmware-session-objects`. Each exposes
only one secure-channel extension so CI can verify the client's strongest-to-
weakest path selection. They are not deployment profiles.

This configurability has three purposes. The baseline catches accidental use
of virtual commands when testing physical compatibility. The secure-channel
profile provides the smallest extension that improves protection of client
credentials. The full profile keeps post-quantum and other experimental
algorithms available without implying that physical firmware implements them.

Device information, command-audit option `0x03`, algorithm-toggle option
`0x04`, and extension capability bits returned by `GetObjectInfo` are filtered
to the compiled firmware profile, including after a state file created by a
different profile is restored. Clients select extensions from active
Authentication Key and source-object capabilities without algorithm marker
values or trial commands.

Extension response codes are the normal request code with bit 7 set. No legacy
aliases or alternate dispatch command exist.

## Post-quantum commands

ML-DSA-44, ML-DSA-65, and ML-DSA-87 use algorithm identifiers 59, 60, and
61. ML-KEM-512, ML-KEM-768, and ML-KEM-1024 use identifiers 62, 63, and 64.
The algorithm identifiers and commands are virtual extensions. Clients expose
the corresponding mechanisms only when the device advertises one or more of
algorithms 59–64. Physical YubiHSM firmware does not advertise those algorithms.

The existing `GenerateAsymmetricKey`, `PutAsymmetricKey`, `GetPublicKey`,
`GetObjectInfo`, listing, deletion, and persistence paths apply unchanged.
Private-key imports carry the 32-byte ML-DSA seed or 64-byte ML-KEM seed.
`GetPublicKey` returns the algorithm byte followed by the raw FIPS public-key
encoding. Object metadata records the seed length while private material stays
inside the HSM object and secure session.

`SignMlDsa` (`0x0d`) has this request body:

```text
key id          u16, big endian
hedge mode      u8   (0 deterministic, 1 randomized required, 2 randomized preferred)
context length  u8
context         context length bytes
message         remaining bytes
```

Its response is the raw FIPS 204 signature. The context is limited to 255
bytes by the one-byte length and FIPS 204. ML-DSA-87 signatures are 4,627 bytes,
so a secure response crosses the former 3,136-byte transport ceiling.

`EncapsulateMlKem` (`0x0e`) takes exactly the big-endian key ID. Its response is
the parameter-set ciphertext followed by the 32-byte shared secret.
`DecapsulateMlKem` (`0x0f`) takes the big-endian key ID followed immediately by
exactly one parameter-set ciphertext and returns the 32-byte shared secret.
Both results travel inside the authenticated and encrypted YubiHSM session.

## Protected volatile derivation objects

The `SessionObject` command lets a client run a chainable derivation graph while
keeping long-term credentials and raw agreements behind the device boundary.
Final working keys may be read once for local message encryption and MAC.

Every request begins with a nested operation byte. Operations that have an
ordinary object equivalent reuse its command code: `GenerateAsymmetricKey`
(`0x46`) generates a P-256 private object, `DeriveEcdh` (`0x57`) creates an
agreement object, and `DeleteObject` (`0x58`) deletes a handle. Session-only
operations use `0x01` read, `0x02` verify AES-CMAC, `0x03` concatenate key,
`0x04` concatenate data, `0x05` extract bits, `0x06` SHA-256, and `0x07`
SP 800-108 counter KDF using AES-CMAC. These values are nested operations,
not independently advertised top-level commands.

Creation operations carry output flags after the nested operation. Bit 0
permits reading, bit 1 permits use as a derivation source, and bit 2 permits
AES-CMAC verification. Derived output then specifies kind (generic secret 1 or
AES 2) and a big-endian `u16` length. P-256 generation instead specifies
algorithm 12 after the flags. Sources are a volatile 64-bit handle (tag 0), a
persistent asymmetric-object ID (tag 1), or a persistent symmetric-object ID
(tag 2). Generated or derived outputs are inserted atomically.

Every envelope request requires `session-objects` in the secure session. A
persistent asymmetric ECDH source also requires `derive-ecdh` on the session
and object, plus normal domain visibility. A persistent symmetric counter-KDF
source similarly requires `encrypt-ecb`; a volatile source requires its derive
flag. Reads require the readable flag. Verification requires an AES object with
the verify flag and accepts CMAC lengths from 1 through 16 bytes.

Each secure session holds at most 64 objects. Handles are random, nonzero
64-bit values and are never persisted or valid in another secure session.
Session close, timeout, authentication replacement or failure, reset, and
protocol invalidation destroy the objects and zeroize secret values. Explicit
deletion requires only a valid owning session and handle.

## Direct PKCS #1 key wrapping

The direct RSA extension wraps only symmetric key material. The wrapping
object is an RSA Public Wrap Key and the unwrapping object is the corresponding
RSA Wrap Key. It does not serialize an asymmetric private key or a complete
YubiHSM object.

No new command or capability is introduced. The reserved zero selector values
distinguish direct RSAES-PKCS1-v1_5 from the physical protocol's RSA-OAEP plus
AES-KWP hybrid format. Clients expose this form only when RSA and at least one
actual virtual key algorithm are present. The direct operation is rejected
while the virtual device's FIPS-mode option is enabled.
