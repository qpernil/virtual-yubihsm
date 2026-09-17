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

## Compiled personas

The default build enables the complete virtual extension set. A stock protocol
persona is built with `--no-default-features`; it advertises only algorithms
1–55 and rejects every extension command as an invalid command. The same flags
are forwarded by the USB worker, I2C frontend, qualification binary, and core:

| Cargo feature | Enabled behavior |
| --- | --- |
| `extended-curves` | X25519, X448, and Ed448 algorithms 56–58 |
| `prefixed-ecdh` | `DeriveEcdhKdf` |
| `session-objects` | The protected volatile-object envelope |
| `secure-channel-derivation` | `prefixed-ecdh` plus `session-objects` |
| `post-quantum` | ML-DSA/ML-KEM algorithms, signing, encapsulation, and decapsulation |
| `direct-rsa-wrap` | The reserved-zero direct RSAES-PKCS1-v1_5 wrap form |
| `full` | Every extension above; this is the default |

For example, `cargo build --no-default-features` produces the stock persona,
while `cargo build --no-default-features --features secure-channel-derivation`
produces a stock-algorithm device with only the two client-side secure-channel
derivation extensions. Device information, command-audit option `0x03`,
algorithm-toggle option `0x04`, and extension capability bits returned by
`GetObjectInfo` are filtered to the compiled persona, including after a state
file created by a different persona is restored. Clients can therefore select
extensions from active Authentication Key and source-object capabilities
without algorithm marker values or trial commands.

The extension commands form one contiguous block in the unused request-code
gap `0x0b`–`0x0f`. Their response codes are the normal request code with bit 7
set. No legacy aliases or alternate dispatch command exist.

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

The `SessionObject` command lets a client run a chainable derivation graph while keeping
long-term credentials and raw agreements behind the device boundary. Final
working keys may be read once for local message encryption and MAC.

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

Every envelope request requires `session-objects` in the secure session. A persistent
asymmetric ECDH source also requires `derive-ecdh` on the
session and object, plus normal domain visibility. A persistent symmetric
counter-KDF source similarly requires `encrypt-ecb`; a volatile source requires
its derive flag. Reads require the readable flag. Verification requires an AES
object with the verify flag and accepts CMAC lengths from 1 through 16 bytes.

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
