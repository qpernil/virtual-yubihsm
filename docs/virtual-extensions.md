# Virtual extensions

The virtual YubiHSM implements the published YubiHSM 2 protocol and also adds
the narrowly scoped extensions below. These additions exist for software-token
use cases and interoperability experiments. They do not imply that a physical
YubiHSM implements the same values or command forms.

| Extension | Discovery | Wire operation | Authorization |
| --- | --- | --- | --- |
| Authentication Key public projection | Support is learned by attempting the operation | `GetPublicKey` with object type `AuthenticationKey` | The Authentication Key must be visible in the session domain |
| X25519 | algorithm 56 | Existing asymmetric-key generate/import/public-key/`DeriveEcdh` commands | Existing generate, put, get-public-key and ECDH capabilities |
| Atomic prefixed ECDH with X9.63 KDF | `DeriveEcdhKdf` (`0x78`) and capability `derive-ecdh-kdf` (`0x38`) | The extension command described in [prefixed ECDH derivation](prefixed-ecdh-derive.md) | `derive-ecdh-kdf` on both the session and source key, plus normal domain visibility |
| Direct RSAES-PKCS1-v1_5 secret-key wrapping | Presence of RSA and any actual virtual key algorithm | `GetRsaWrappedKey` and `PutRsaWrappedKey` with their normally nonzero hybrid-wrap selector fields set to zero | Existing `export-wrapped`/`import-wrapped` permissions; the source key also needs `exportable-under-wrap`, and delegated-capability/domain rules remain in force |
| X448 | algorithm 57 | Existing asymmetric-key generate/import/public-key/`DeriveEcdh` commands | Existing generate, put, get-public-key and ECDH capabilities |
| Ed448 | algorithm 58 | Existing asymmetric-key generate/import/public-key/`SignEddsa` commands | Existing generate, put, get-public-key and EdDSA-sign capabilities |
| Protected volatile derivation objects | Commands `DeriveSessionObject` (`0x79`), `ReadSessionObject` (`0x7a`), `VerifySessionObject` (`0x7b`), and `DeleteSessionObject` (`0x7c`), capability `derive-session-key` (`0x39`) | Session-scoped P-256 generation/ECDH, generic-secret or AES composition and derivation, controlled reads, AES-CMAC verification, and deletion | `derive-session-key` on the authenticated session; persistent ECDH and AES sources additionally require their ordinary operation capability and domain visibility |
| ML-DSA and ML-KEM | ML-DSA algorithms 59–61 and ML-KEM algorithms 62–64 | Existing asymmetric-key generation, seed import, public-key and object commands; `SignMlDsa` (`0x7d`) and `MlKem` (`0x7e`) | Existing generate/put/delete permissions plus `sign-ml-dsa` (`0x3a`), `encapsulate-ml-kem` (`0x3b`), or `decapsulate-ml-kem` (`0x3c`) on both the session and private-key object |

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

`SignMlDsa` (`0x7d`) has this request body:

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

`MlKem` (`0x7e`) starts with a big-endian key ID and an operation byte. Operation
0 is encapsulation and permits no trailing request data; its response is the
parameter-set ciphertext followed by the 32-byte shared secret. Operation 1 is
decapsulation and requires exactly one parameter-set ciphertext; its response
is the 32-byte shared secret. Both results travel inside the authenticated and
encrypted YubiHSM session.

The response codes are `0xfd` and `0xfe`. Command `0x7f` remains unused because
setting its response bit would collide with the protocol error response
`0xff`.

## Protected volatile derivation objects

These commands let a client run a chainable derivation graph while keeping
long-term credentials and raw agreements behind the device boundary. Final
working keys may be read once for local message encryption and MAC.

`DeriveSessionObject` starts with an operation byte and output flags. Bit 0
permits reading, bit 1 permits use as a derivation source, and bit 2 permits
AES-CMAC verification. Output kinds are generic secret (1) and AES (2); P-256
private objects are produced only by the generation operation. Sources are a
volatile 64-bit handle (tag 0), a persistent asymmetric-object ID (tag 1), or a
persistent symmetric-object ID (tag 2). The operations are P-256 generation
(1), ECDH (2), concatenate base and key (3), concatenate base and data (4),
extract bits (5), SHA-256 (6), and SP 800-108 counter KDF using AES-CMAC (7).
Generated or derived outputs are inserted atomically.

Every command requires `derive-session-key` in the secure session. A persistent
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
