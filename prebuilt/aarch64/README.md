# ARM64 I2C service binary

`virtual-yubihsm-i2c` is a convenience build for the small Raspberry Pi target
machines, where compiling the Rust cryptographic dependency graph is not
practical. The kernel module remains a separate C build from
`raspberry-pi-i2c-target`.

The binary supports both `--inherited-device` for supervisor profiles and
`--device` for direct device-path opening.

The binary was built from clean `virtual-yubihsm` commit
`68b9222` on `ubuntu4`, running Ubuntu
26.04.1 LTS on ARM64, with Rust and Cargo 1.98.1 and glibc 2.43. Its path
dependencies were:

- `software-key-core` at `d7ccb93f42ab425f26c8dbd9c356c1d833d74eee`;
- `usb-gadget-supervisor` at `2f92928`.

It is an AArch64 PIE executable. ELF version inspection shows it
requires at most `GLIBC_2.34`, which is compatible with the Raspberry Pi OS
Debian 13 targets using glibc 2.41.

Verify it before installation:

```sh
(cd prebuilt/aarch64 && sha256sum -c SHA256SUMS)
```

GitHub `main` remains the source of truth. A capable ARM64 build machine should
normally use:

```sh
cargo build --release --locked -p virtual-yubihsm-i2c
```
