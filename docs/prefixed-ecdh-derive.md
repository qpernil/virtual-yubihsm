# Prefixed ECDH derivation

## Status and purpose

The virtual YubiHSM implements a `DeriveEcdhKdf` extension command. A future
PKCS11RS provider mechanism maps directly onto this command:

```text
CKM_PKCS11RS_PREFIXED_ECDH_DERIVE
CK_PKCS11RS_PREFIXED_ECDH_DERIVE_PARAMS
```

The operation performs one ECDH agreement with a private key held by the HSM,
prefixes its raw shared secret with caller-supplied secret material, and applies
a mandatory ANSI X9.63 KDF. The raw HSM-computed ECDH secret never crosses the
device boundary.

This is deliberately a generic ECDH derivation mechanism rather than an SCP11
mechanism. SCP11 asymmetric authentication is its first intended consumer.

## Cryptographic operation

For the HSM-held private key `d`, peer public key `Q`, caller prefix `P`, shared
data `S`, and requested output length `L`:

```text
Z       = ECDH(d, Q)
block_i = Hash(P || Z || I2OSP(i, 4) || S), i = 1, 2, ...
output  = leftmost L bytes of block_1 || block_2 || ...
```

This is ANSI X9.63 applied to the composite secret `P || Z`. The prefix and
shared data occupy different positions: `P` precedes the HSM-confined secret,
while `S` follows the X9.63 counter. There is no additional append field.

A real hash-based KDF is mandatory. Neither the wire command nor the proposed
PKCS#11 mechanism accepts a null KDF. Empty prefix and shared-data values are
valid, but the result remains `KDF(Z)` and never becomes raw ECDH output.

## Proposed PKCS#11 interface

The provider-facing parameter structure is:

```c
typedef struct CK_PKCS11RS_PREFIXED_ECDH_DERIVE_PARAMS {
    CK_EC_KDF_TYPE kdf;
    CK_ULONG ulSharedDataLen;
    CK_BYTE_PTR pSharedData;
    CK_ULONG ulPublicDataLen;
    CK_BYTE_PTR pPublicData;
    CK_ULONG ulPrefixDataLen;
    CK_BYTE_PTR pPrefixData;
} CK_PKCS11RS_PREFIXED_ECDH_DERIVE_PARAMS;
```

The mechanism is used through `C_DeriveKey`. The base object is the HSM-held
private key. The output length and output key type come from the ordinary
derived-key template. The initial provider implementation should accept the
same ANSI X9.63 `CKD_*_KDF` values as `CKM_ECDH1_DERIVE`, but must reject
`CKD_NULL` and the differently ordered SP 800-56A variants.

The mechanism is vendor-qualified and intentionally does not contain `ECDH1`,
`ECDH2`, or `ECDH3`. Those names could incorrectly imply compatibility with
the standard numbered ECDH parameter structures or a particular number of key
pairs.

## PKCS#11-to-HSM mapping

| PKCS#11 input | Virtual YubiHSM input |
| --- | --- |
| `hBaseKey` | asymmetric-key object ID |
| `params.kdf` | X9.63 hash selector |
| derived template `CKA_VALUE_LEN` | output length |
| `pPublicData` | peer public key |
| `pPrefixData` | prefix data |
| `pSharedData` | X9.63 shared data |
| derived object | command response bytes wrapped as a PKCS#11 key object |

The provider normalizes `pPublicData` in the same way as ordinary ECDH before
encoding the HSM command. For short-Weierstrass curves the command receives a
SEC1 public point; for X25519 it receives the raw 32-byte public value.

The proposed key-capability mapping is:

- an asymmetric key restricted to
  `CKM_PKCS11RS_PREFIXED_ECDH_DERIVE` receives `derive-ecdh-kdf` but not
  `derive-ecdh`;
- a discovered key with `derive-ecdh-kdf` has `CKA_DERIVE=CK_TRUE` and advertises
  the prefixed mechanism through `CKA_ALLOWED_MECHANISMS`;
- ordinary `derive-ecdh` remains mapped to standard raw ECDH mechanisms;
- a key intentionally carrying both HSM capabilities may use both mechanism
  families.

## Virtual YubiHSM wire extension

The extension uses:

```text
command code       0x78  DeriveEcdhKdf
capability bit     0x38  derive-ecdh-kdf
algorithm advert   57    ECDH KDF extension present
```

The authenticated request is big-endian and has this format:

```text
offset  length  field
0       2       asymmetric-key object ID
2       1       X9.63 hash selector
3       2       requested output length
5       2       peer-public length
7       2       prefix length
9       2       shared-data length
11      ...     peer public || prefix || shared data
```

Hash selectors are:

| Value | Hash |
| ---: | --- |
| 1 | SHA-1 |
| 2 | SHA-224 |
| 3 | SHA-256 |
| 4 | SHA-384 |
| 5 | SHA-512 |
| 6 | SHA3-224 |
| 7 | SHA3-256 |
| 8 | SHA3-384 |
| 9 | SHA3-512 |

The response is exactly the requested KDF output. Authorization requires
`derive-ecdh-kdf` on both the authenticated session and the asymmetric-key
object, plus the normal shared-domain check. Raw `DeriveEcdh` independently
requires `derive-ecdh`; possession of only the new capability cannot disclose
`Z`.

## SCP11/YubiHSM asymmetric-authentication mapping

For YubiHSM asymmetric authentication:

```text
P = Zephemeral
Z = Zstatic
S = 3c 88 10
L = 64
Hash = SHA-256
```

The connector generates a client ephemeral P-256 key and computes
`Zephemeral` from the target's fresh ephemeral public key. It invokes
`DeriveEcdhKdf` on the source HSM using the protected client-static private key
and the target's static device public key. The 64-byte response contains:

```text
0..16   receipt key
16..32  S-ENC
32..48  S-MAC
48..64  S-RMAC
```

The connector validates the target receipt with the first key and uses the
remaining keys for that secure session. It erases the derived material and its
client ephemeral private key when the session ends.

The receipt and secure-messaging calculations are, in wire order:

```text
Kreceipt = output[0..16]
S-ENC    = output[16..32]
S-MAC    = output[32..48]
S-RMAC   = output[48..64]

receipt = AES-CMAC(Kreceipt,
                   Qdevice-ephemeral || Qclient-ephemeral)
```

The full 16-byte receipt becomes the initial MAC chaining value `MCV`. For each
authenticated request, let `R` be the encoded three-byte command header and
payload, with the header length including the trailing eight-byte MAC but with
that MAC itself omitted from `R`:

```text
command-mac = AES-CMAC(S-MAC, MCV || R)
wire-mac    = command-mac[0..8]
next MCV    = command-mac
```

For a response, let `A` be its encoded three-byte response header and payload,
again with the header length including the trailing eight-byte response MAC
but with that MAC omitted from `A`:

```text
response-mac = AES-CMAC(S-RMAC, MCV || A)
wire-rmac    = response-mac[0..8]
```

Response authentication does not advance `MCV`; the next request advances it.
For an encrypted session message, the inner YubiHSM frame is padded using ISO
7816-4 padding and encrypted with AES-CBC under `S-ENC`:

```text
IV         = AES-ECB(S-ENC, counter)
ciphertext = AES-CBC-ENC(S-ENC, IV, ISO7816-4-pad(inner-frame))
```

The request and its response use the same counter-derived IV. The counter
starts at one and increments after each completed request/response exchange.

## Security boundary

The separate capability is essential. If the same key also has ordinary
`derive-ecdh`, a caller can request reusable `Zstatic` directly and the stronger
property is intentionally lost.

With only `derive-ecdh-kdf`, retaining all externally visible transcript data,
the client ephemeral private key, `Zephemeral`, and even the resulting session
keys compromises at most the corresponding live session. A new target session
uses a fresh target ephemeral key and therefore a new prefix. An old result

```text
Hash(old-prefix || Zstatic || counter || SharedInfo)
```

cannot be transformed into the result for a new prefix without recovering the
high-entropy `Zstatic` or breaking the hash. SHA-256 length extension can only
append after the complete old input; it cannot replace the prefix before the
unknown static secret, and its padded extension is not a valid SCP11 input.

The construction assumes validated peer public keys, fresh target ephemeral
keys, non-replayable closed sessions, and no continuing authorization to invoke
the source HSM. A compromised connector holding the exported session keys can
still control the current session; avoiding that would require moving secure
messaging itself behind the HSM boundary.

## Future true key derivation

The broader missing HSM abstraction is a real, chainable `C_DeriveKey`: a
protected base object plus mechanism parameters and an output template should
create another protected HSM object atomically instead of returning bytes. A
persistent generic-secret object type would provide the natural intermediate
object. This is realistic for physical hardware: it is an ordinary,
non-extractable NVM object with narrowly assigned derivation capabilities, not
a large or long-lived RAM allocation.

For this construction, a token-output form of `DeriveEcdhKdf` would create the
64-byte generic secret directly in NVM. Native `CKM_EXTRACT_KEY_FROM_KEY` could
then create persistent, non-extractable AES-128 objects for the receipt key,
`S-ENC`, `S-MAC`, and `S-RMAC`. Existing AES-CMAC, ECB, and CBC operations would
complete secure messaging without exposing any key bytes.

The generic-secret output could itself serve as an HMAC or KDF base key. A
subsequent derivation could instead create AES or another supported symmetric
key type selected by the output template. The same foundation should cover
standard protected ECDH and finite-field DH, HKDF, all three SP 800-108 modes,
`CKM_EXTRACT_KEY_FROM_KEY`, concatenate/XOR composition, digest-based
derivation, and suitable protocol-specific derivations. Password-based input
can produce the same persistent output objects even though its operation is
closer to key generation than derivation from a protected base key.

Ordinary derived token objects would follow the usual YubiHSM model:
NVM-backed, generation-tracked, and explicitly deleted. A practical first
subset is persistent generic-secret output, extraction into persistent AES
keys, protected ECDH, HKDF, and SP 800-108. That is broadly reusable and
happens to provide all the key-composition pieces SCP11 needs without making
SCP11 itself part of the object model.

The one session object needed by the SCP11 construction is small enough for a
more faithful hardware design. Each authenticated HSM session can hold one
optional, zeroizing generic-secret buffer of at most 64 bytes. It has sequence
zero, never enters persistence, and is addressable only through that HSM
session. Authentication clears it before establishing new authority; close,
timeout, authentication failure, protocol invalidation, and reset clear it as
well. The provider must retain the underlying HSM session while its PKCS #11
session-object handle exists. The generic secret can then be extracted into
ordinary persistent AES objects without its bytes crossing the device
boundary. This requires no NVM orphan recovery or persistent session-owner
metadata.
