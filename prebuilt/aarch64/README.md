# ARM64 I2C service binary

`virtual-yubihsm-i2c` is a release build for small Raspberry Pi targets. It
supports `--inherited-device` for supervisor profiles and `--device` for direct
opening. The default `firmware-full` profile and shared persistent runtime are
included. The kernel module remains a separate target-local C build from
`raspberry-pi-i2c-target`.

Built from clean `virtual-yubihsm` source commit
`ea1c7c67fd6b52a43b2da54c80c2c94917577881` on `ubuntu4`, Ubuntu 26.04.1 LTS ARM64,
with Rust/Cargo 1.99.0 and glibc 2.43. Its `software-key-core` path dependency
was at `40f84378086c76f7b4c64ec45141c9f7815a1e46`; other cryptographic
revisions are pinned by the checked-in Cargo.lock.

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
