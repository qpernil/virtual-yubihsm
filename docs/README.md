# Documentation

- [Connector integration](pkcs11rs-connector-integration.md) - persistent
  Virtual YubiHSM instances embedded in `pkcs11rs-connector`, including
  configuration, ownership, durability, and lifecycle.
- [Qualification](qualification.md) - transport-independent conformance
  scenarios for the core, connector, USB gadget, and physical devices.
- [Virtual extensions](virtual-extensions.md) - firmware profiles and the
  command, algorithm, and capability surface beyond physical YubiHSM 2
  firmware.
- [Prefixed ECDH derivation](prefixed-ecdh-derive.md) - protected client-side
  derivation used by pkcs11rs SCP03 and SCP11 authentication.
- [Wrapped-object format](wrapped-object-format.md) - canonical virtual-device
  wrapping representation and strict decoding rules.
- [Object-info lengths](object-info-lengths.md) - compatibility rules for
  object sizes reported by the protocol.
- [Asymmetric credential qualification](advanced-yubihsm-auth-qualification.md)
  - SCP11-style P-256 authentication paths and persistence checks.
- [Experimental I2C transport](i2c.md) - Raspberry Pi BSC target wiring,
  lifecycle, service installation, and hardware validation.
