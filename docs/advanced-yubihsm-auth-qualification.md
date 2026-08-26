# Advanced YubiHSM Auth qualification

On 2026-08-25 and 2026-08-26, the persisted asymmetric-authentication path was
qualified end to end with a physical YubiKey and the USB Virtual YubiHSM.

## Setup

- Virtual YubiHSM firmware identity: 2.4.1
- Virtual YubiHSM USB serial: `12345678`
- Physical YubiKey firmware: 5.7.4
- Existing asymmetric YubiHSM Auth credential: `hsmauth-37987918`
- Provisioned Virtual YubiHSM Authentication Key ID: `0x1234`
- Physical YubiHSM serials `1238075073` and `2545354682` were subsequently
  attached to the Ubuntu3 PKCS11RS connector and provisioned with the same
  public credential at Authentication Key ID `0x1234`.

The existing YubiKey credential was reused without replacement. The ignored
`pkcs11rs` hardware test
`provisions_asymmetric_hsmauth_credential_on_yubihsm` read its P-256 public
key, installed the matching asymmetric Authentication Key, established a real
asymmetric session, stored the synthetic public-key companion used by
`pkcs11rs`, and verified public-key discovery.

Authentication Key `0x1234` covers all 16 domains. Its capabilities and
delegated capabilities permit the non-administrative application operations
implemented by the device: object lifecycle for opaque, asymmetric, wrapping,
HMAC, template, OTP AEAD, symmetric, and public wrapping keys; signing,
decryption, ECDH, wrapping, AES, HMAC, OTP, and attestation operations; option
and audit reads; and pseudo-random generation. Administrative credential
management, device reset, and option mutation remain excluded.

Replacing the Virtual YubiHSM Authentication Key advanced its sequence from
`0` to `1`. The synthetic public-key companion at the same numeric ID but a
different object type remained present. This also qualified the global
per-numeric-ID generation rule and the corrected deletion authorization rule:
an authorized administrative session can replace an object even when the
target object does not delegate its own deletion.

## Persistence check

After successful provisioning, the Virtual YubiHSM service was restarted so
the next session had to load the Authentication Key from its durable version-1
CBOR image. `yubihsm-shell` used the unchanged physical credential to open an
asymmetric session and complete `Get Pseudo Random` both before and after the
restart. Post-restoration object information still reported sequence `1` and
the expanded capabilities.

Both physical YubiHSMs accepted the same asymmetric Authentication Key and
capability set. PKCS11RS modern connector discovery exposed them independently
at `/v1/devices/1238075073` and `/v1/devices/2545354682`; the installed iPhone
smoke applications use that multi-device API through Ubuntu3.

## Result

Passed. Provisioning, expanded authorization, asymmetric YubiHSM Auth session
establishment, synthetic public-key discovery, global object-ID generation,
durable state restoration, and authentication with the persisted key all
behaved as intended.
