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
