# ARM64 I2C service binary

`virtual-yubihsm-i2c` is a convenience build for the small Raspberry Pi target
machines, where compiling the Rust cryptographic dependency graph is not
practical. The kernel module remains a separate C build from
`raspberry-pi-i2c-target`.

The binary supports both `--inherited-device` for supervisor profiles and
`--device` for direct device-path opening.

The binary was built from clean `virtual-yubihsm` commit
`b66184dc9b8029547377528e9e13259cd8e9adc5` on `ubuntu4`, running Ubuntu
26.04 LTS on ARM64, with Rust and Cargo 1.98.1 and glibc 2.43. Its path
dependency was:

- `software-key-core` at `21d14c6af8a814b11459fb8ccb16475359f45835`.

It is an AArch64 PIE executable. ELF version inspection shows it
requires at most `GLIBC_2.34`, which is compatible with the Raspberry Pi OS
Debian 13 targets using glibc 2.41.

Verify it before installation:

```sh
(cd prebuilt/aarch64 && sha256sum -c SHA256SUMS)
```

GitHub `main` remains the source of truth. Build this artifact on a capable
ARM64 machine with:

```sh
cargo build --release --locked -p virtual-yubihsm-i2c
```

Do not run Rust builds on `raspberrypi-1` or `raspberrypi-2`; they do not have
enough RAM for the Rust dependency graph. Build on `ubuntu4`, update this binary
and its checksum in the canonical Mac repository, commit and push them, and let
the Raspberry Pis receive the prebuilt through Git.
