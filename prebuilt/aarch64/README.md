# ARM64 I2C service binary

`virtual-yubihsm-i2c` is a release build for small Raspberry Pi targets. It
supports `--inherited-device` for supervisor profiles and `--device` for direct
opening. The default `firmware-full` profile and shared persistent runtime are
included. The kernel module remains a separate target-local C build from
`raspberry-pi-i2c-target`.

Built from clean `virtual-yubihsm` source commit
`c71047fb26524c7a4100930ce6286dc8e22f0c7a` on `ubuntu4`, Ubuntu 26.04.1 LTS ARM64,
with Rust/Cargo 1.99.0 and glibc 2.43. Its `software-key-core` path dependency
was at `4e7a79348e90eea1f608c24d2aaeb6d3c803d994`; other cryptographic
revisions are recorded in Cargo.lock at that source commit. Standalone
ML-DSA/ML-KEM imports accept seeds, expanded keys, and consistent combined forms;
persistent records preserve keys whose seed is unavailable. The build's lockfile
includes ML-KEM 0.3.3 with arithmetic CBD sampling and patched constant-time
arithmetic dependencies.
This binary uses the minimal ML-DSA matrix stack-usage PR at
`a08a14910652a3737b8de83d18ad33704853d9db`; expanded-key import validation
is implemented by `software-key-core` using the dependency's public API.
Current source uses upstream RustCrypto/signatures without a revision pin;
rebuild the binary to incorporate the resolved upstream dependency.

The AArch64 PIE executable requires at most `GLIBC_2.34`, compatible with
Raspberry Pi OS Debian 13 using glibc 2.41. Verify before installation:

```sh
(cd prebuilt/aarch64 && sha256sum -c SHA256SUMS)
```

Rebuild on a capable ARM64 machine with:

```sh
cargo build --release --locked -p virtual-yubihsm-i2c
```

Do not run Rust builds on `raspberrypi-1` or `raspberrypi-2`; they do not have
enough RAM for the dependency graph. Build on `ubuntu4`, update the binary,
checksum and provenance in the canonical Mac repository, then commit and push.
Targets receive the prebuilt through Git. Preserve device state and service
activation; restart an active profile after replacing a changed binary.
