# Virtual extensions

The virtual YubiHSM implements the published YubiHSM 2 protocol and also adds
the narrowly scoped extensions below. These additions exist for software-token
use cases and interoperability experiments. They do not imply that a physical
YubiHSM implements the same values or command forms.

| Extension | Discovery | Wire operation | Authorization |
| --- | --- | --- | --- |
| Authentication Key public projection | Support is learned by attempting the operation | `GetPublicKey` with object type `AuthenticationKey` | The Authentication Key must be visible in the session domain |
| X25519 | algorithm 56 | Existing asymmetric-key generate/import/public-key/`DeriveEcdh` commands | Existing generate, put, get-public-key and ECDH capabilities |
| Atomic prefixed ECDH with X9.63 KDF | algorithm 57, command `DeriveEcdhKdf` (`0x78`) and capability `derive-ecdh-kdf` (`0x38`) | The extension command described in [prefixed ECDH derivation](prefixed-ecdh-derive.md) | `derive-ecdh-kdf` on both the session and source key, plus normal domain visibility |
| Direct RSAES-PKCS1-v1_5 secret-key wrapping | algorithm 58 | `GetRsaWrappedKey` and `PutRsaWrappedKey` with their normally nonzero hybrid-wrap selector fields set to zero | Existing `export-wrapped`/`import-wrapped` permissions; the source key also needs `exportable-under-wrap`, and delegated-capability/domain rules remain in force |
| X448 | algorithm 59 | Existing asymmetric-key generate/import/public-key/`DeriveEcdh` commands | Existing generate, put, get-public-key and ECDH capabilities |
| Ed448 | algorithm 60 | Existing asymmetric-key generate/import/public-key/`SignEddsa` commands | Existing generate, put, get-public-key and EdDSA-sign capabilities |
| Protected volatile derivation objects | algorithm 61, commands `DeriveSessionObject` (`0x79`), `ReadSessionObject` (`0x7a`), `VerifySessionObject` (`0x7b`), and `DeleteSessionObject` (`0x7c`), capability `derive-session-key` (`0x39`) | Session-scoped P-256 generation/ECDH, generic-secret or AES composition and derivation, controlled reads, AES-CMAC verification, and deletion | `derive-session-key` on the authenticated session; persistent ECDH and AES sources additionally require their ordinary operation capability and domain visibility |

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

Every command requires algorithm 61 and `derive-session-key` in the secure
session. A persistent asymmetric ECDH source also requires `derive-ecdh` on the
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
AES-KWP hybrid format. Algorithm 58 is a discovery marker so clients can expose
this behavior only for a virtual device; clients must not infer it merely from
the presence of RSA wrapping commands on physical firmware.

The marker is suppressed, and the direct operation is rejected, while the
virtual device's FIPS-mode option is enabled.
