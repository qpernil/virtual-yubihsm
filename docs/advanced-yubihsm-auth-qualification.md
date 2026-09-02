# Asymmetric credential qualification

The managed qualification set uses the same asymmetric credential layout on
the USB Virtual YubiHSM and the two reference devices. Each device has exactly
seven provisioned objects and no qualification-owned temporary objects.

## Authentication credentials

| ID | Label | Provider | Authority |
| ---: | --- | --- | --- |
| `0001` | `pkcs11rs public discovery` | Password-derived symmetric keys | Public discovery only |
| `1001` | `hsmauth-37070618` | YubiHSM Auth credential | Administration and normal operations |
| `1002` | `hsmauth-37987918` | YubiHSM Auth credential | Administration and normal operations |
| `1003` | `reserve` | Platform-protected P-256 credential | Administration and normal operations |

The three asymmetric credentials cover every domain and carry the complete
capability and delegated-capability sets. A password can therefore discover
public metadata but cannot perform cryptographic or administrative operations.
All stronger access begins with a private key that remains inside its provider.

Each asymmetric Authentication Key has a separate Opaque public projection.
The projection lets PKCS11RS match a provider credential to a target
Authentication Key before login without making the private key exportable.

## Qualified paths

Both YubiHSM Auth credentials independently establish authenticated encrypted
sessions on all three devices. The native adapter asks the YubiKey to validate
the device receipt and return the three per-session transport keys; the static
credential key is never returned to the host.

The `reserve` credential independently establishes the same sessions on all
three devices. On Apple platforms its static P-256 private key remains in the
Secure Enclave. The platform provider performs ECDH and the prefixed X9.63
derivation, then returns only the per-session transport keys to the protocol
client. Its public key remains exportable so the credential can be reprovisioned
after a device reset.

The restricted discovery credential can enumerate the provisioned public
objects and is denied a normal cryptographic command. The managed qualification
profile verifies encrypted command transport, authorization capabilities,
delegation, domains, object lifecycle, official cryptographic operations, and
cleanup. The extension profile is reported separately.

## Persistence and cleanup

The Virtual YubiHSM persists the same seven-object layout through its ordinary
state store. Qualification scenarios reserve the `qualification` label prefix
for temporary objects and normally delete them before closing their session.
After an interrupted run, `yubihsm-qualification cleanup` removes only objects
with that prefix and reports the remaining object count.
