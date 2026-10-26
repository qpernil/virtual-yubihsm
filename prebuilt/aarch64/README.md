# ARM64 I2C service binary

`virtual-yubihsm-i2c` is a release build for small Raspberry Pi targets. It
supports `--inherited-device` for supervisor profiles and `--device` for direct
opening. The default `firmware-full` profile and shared persistent runtime are
included. The kernel module remains a separate target-local C build from
`raspberry-pi-i2c-target`.

Built from clean `virtual-yubihsm` source commit
`2a194b2d19d0f8947dad2c8805c69012d0cb5bb8` on `ubuntu4`, Ubuntu 26.04.1 LTS ARM64,
with Rust/Cargo 1.99.1 and glibc 2.43. Its `software-key-core` path dependency
was at `1a8746639730a1f210cb0af45decb2ee1c5b0990`; other cryptographic
revisions are recorded in Cargo.lock at that source commit.

ML-DSA follows the upstream
[RustCrypto/signatures](https://github.com/RustCrypto/signatures) default branch
without a revision pin. This build resolves upstream commit
`7b8bdcde8917a9db5775e689e25c91adb784492a`, including row-allocated matrices to
limit stack usage. Expanded-key import validation is implemented by
`software-key-core` using the dependency's public API. Standalone ML-DSA/ML-KEM
imports accept seeds, expanded keys, and consistent combined forms; persistent
records preserve keys whose seed is unavailable. The build's lockfile includes
ML-KEM 0.3.3 with arithmetic CBD sampling and patched constant-time arithmetic
dependencies.

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
