# ARM64 I2C service binary

`virtual-yubihsm-i2c` is prebuilt only for `raspberrypi-1` and `raspberrypi-2`.
Every other lab host builds its worker locally. This release build
supports `--inherited-device` for supervisor profiles and `--device` for direct
opening. The default `firmware-full` profile and shared persistent runtime are
included. The frontend supports explicit response recovery with the driver recovery ioctl.
The frontend supports explicit response recovery with the driver recovery ioctl.
The kernel module remains a separate target-local C build from
`raspberry-pi-i2c-target`.

Built on `ubuntu4`, Ubuntu 26.04.1 LTS ARM64, with Rust 1.99.1, Cargo 1.99.1,
and glibc 2.43, from these clean source revisions:

| Build input | Commit |
| --- | --- |
| `virtual-yubihsm` | `cc3f9fe6f26c1c3f845069db60a82197d6a54e86` |
| `software-key-core` | `59a0521b89c5a62e2ebfa522f396b2c2c34a5cb4` |

The source commit's `Cargo.lock` records the dependency resolution. ML-DSA is
pinned to upstream RustCrypto/signatures commit
`a3690c4a0bd861fcf2bde0e38b3609e86c3fe89e`, retaining the matrix stack fix.
The lockfile includes `crypto-bigint` 0.7.10, `elliptic-curve` 0.14.3,
`der` 0.8.3, and ML-KEM 0.3.3. Expanded-key validation and persistent storage
remain in the shared core; seeds, expanded keys, and consistent combined forms
are supported, including keys whose seed is unavailable.

The AArch64 PIE executable requires at most
`GLIBC_2.34`, compatible with Raspberry Pi OS Debian 13 using glibc 2.41.
Verify before installation:

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
