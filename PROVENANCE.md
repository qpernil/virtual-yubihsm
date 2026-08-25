# Source and compatibility boundary

Virtual YubiHSM is an independent compatibility implementation. Its
implementation sources are public standards, public vendor documentation,
ordinary host APIs, and black-box interoperability tests.

No proprietary firmware source code, internal documentation, cryptographic
keys, attestation certificates, or other confidential material is included in,
required to build, or accepted as an implementation source for this
repository.

Compatibility validation uses normal documented clients and independently
observed protocol exchanges. Protocol facts and test transcripts become
independently written Rust code and regression tests; vendor source code is not
copied.

This policy describes the project's source boundary and does not claim a
formally supervised two-team clean-room process.
