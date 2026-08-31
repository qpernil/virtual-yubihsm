# Virtual wrapped-object format

Full-object wrapping uses a private virtual-device format. It is deliberately
separate from the internal wrapped-object representation of a physical
YubiHSM.

The plaintext is a definite-length canonical CBOR array:

```text
[
  "virtual-yubihsm-object",
  1,
  object_type,
  object_id,
  domains,
  capabilities,
  algorithm,
  origin,
  label,
  delegated_capabilities,
  material
]
```

`object_type`, `algorithm`, and `origin` are unsigned 8-bit values. `object_id`
and `domains` are unsigned 16-bit values. Capability sets are their exact
eight-byte protocol bitmaps. The label is a byte string of at most 40 bytes;
it is not required to be text. Only the low origin nibble is serialized.

`length` is derived again from the object type, algorithm, and material.
`sequence` belongs to the receiving device's object-generation history and is
assigned when the object is installed, so neither field is serialized.

## Material variants

Material is another definite-length CBOR array whose first element is its
unsigned variant number:

| Variant | CBOR value | Use |
| ---: | --- | --- |
| 0 | `[0, bytes]` | AES symmetric keys, HMAC keys, and AES-CCM wrap keys |
| 1 | `[1, pkcs8_der]` | Asymmetric private keys and private RSA wrap keys |
| 2 | `[2, bytes]` | Opaque and template objects |
| 3 | `[3, modulus]` | Public RSA wrap keys |
| 4 | `[4, key]` | Symmetric authentication keys (`K-ENC || K-MAC`) |
| 5 | `[5, point]` | P-256 authentication public keys (`x || y`) |
| 6 | `[6, nonce_id, key]` | OTP AEAD keys |

Private RSA, Weierstrass EC, Ed25519, and X25519 keys use canonical bare
PKCS #8 DER. X25519 follows RFC 8410. The decoder verifies that the PKCS #8
algorithm and parameters agree with the YubiHSM algorithm in the outer record.
RSA keys must have the expected modulus size and public exponent 65537.

Symmetric key material is raw, matching the key-only RSA-wrapped-key commands.
A public RSA wrap key is also stored in its native virtual-device form: the
raw fixed-width modulus. Its algorithm supplies the modulus size and its public
exponent is implicitly 65537. SPKI is produced at public-key API boundaries and
is not duplicated inside this private full-object format.

## Strict decoding

The decoder accepts exactly one CBOR value and rejects:

- indefinite or otherwise noncanonical encodings;
- trailing bytes;
- an unknown schema, version, object type, algorithm, or material variant;
- a material variant inconsistent with the object type or algorithm;
- invalid key lengths, authentication points, or PKCS #8 values; and
- reserved high origin bits.

After decoding and validation, the logical object is encoded again and the
result must exactly equal the input bytes. This also makes the nested PKCS #8
representation canonical.

## Cryptographic framing

The CBOR value is plaintext only at the internal codec boundary. The wrapping
commands protect it using their existing mechanisms:

- AES-CCM full-object wrapping returns `1 || nonce || ciphertext || tag`.
- RSA full-object wrapping protects the same CBOR plaintext with the existing
  RSA-OAEP plus AES-KWP hybrid construction.

The key-only RSA commands do not use this CBOR record. They wrap PKCS #8 DER
for asymmetric private keys and raw bytes for symmetric keys, with object
metadata supplied separately on import.
