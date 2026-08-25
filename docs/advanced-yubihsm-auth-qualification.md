# Advanced YubiHSM Auth qualification

On 2026-08-25, the persisted asymmetric-authentication path was qualified end
to end with a physical YubiKey and the USB Virtual YubiHSM.

## Setup

- Virtual YubiHSM firmware identity: 2.4.1
- Virtual YubiHSM USB serial: `12345678`
- Physical YubiKey firmware: 5.7.4
- Existing asymmetric YubiHSM Auth credential: `hsmauth-37987918`
- Provisioned Virtual YubiHSM Authentication Key ID: `0x1234`
- No physical YubiHSM was attached, so the virtual device was the only HSM
  provisioning target.

The existing YubiKey credential was reused without replacement. The ignored
`pkcs11rs` hardware test
`provisions_asymmetric_hsmauth_credential_on_yubihsm` read its P-256 public
key, installed the matching asymmetric Authentication Key, established a real
asymmetric session, stored the synthetic public-key companion used by
`pkcs11rs`, and verified public-key discovery.

Authentication Key `0x1234` was intentionally restricted to these capabilities
and delegated capabilities:

```text
put-opaque:get-opaque:delete-opaque
```

It covers all 16 domains.

## Persistence check

After successful provisioning, the Virtual YubiHSM service was restarted so
the next session had to load the Authentication Key from its durable version-1
CBOR image. `yubihsm-shell` then used the unchanged credential on the physical
YubiKey to open session 0 through `yhusb://serial=12345678` with Authentication
Key `0x1234`. This confirmed that the asymmetric key survived persistence and
remained usable after restart.

A subsequent `Get Pseudo Random` request returned `Wrong permissions for
operation`, as expected: session creation had already succeeded, while this
deliberately narrow Authentication Key does not carry the `get-pseudo-random`
capability.

## Result

Passed. Provisioning, asymmetric YubiHSM Auth session establishment, synthetic
public-key discovery, durable state restoration, and authentication with the
persisted key all behaved as intended.
