# Object sizes reported by YubiHSM 2

This table records the `length` returned by `GetObjectInfo` on a physical
YubiHSM 2 running firmware 2.5.0. The measurements were made on 2026-08-31.
These values are object metadata; they are not protocol input lengths.

In the formulas below, `n` is the RSA modulus length in bytes, `c` is an
elliptic-curve coordinate length in bytes, `k` is the stored key material
length, and `b` is the HMAC algorithm's block length.

## Authentication keys

| Algorithm | Reported length | Formula |
| --- | ---: | --- |
| `aes128-yubico-authentication` | 40 | `k + 8`, where `k = 32` |
| `ecp256-yubico-authentication` | 72 | `k + 8`, where `k = 64` |

## Asymmetric keys

| Algorithm | Reported length | Formula |
| --- | ---: | --- |
| `rsa2048` | 896 | `7n / 2` |
| `rsa3072` | 1,344 | `7n / 2` |
| `rsa4096` | 1,792 | `7n / 2` |
| `ecp224` | 84 | `3c` |
| `ecp256` | 96 | `3c` |
| `ecp384` | 144 | `3c` |
| `ecp521` | 198 | `3c` |
| `eck256` | 96 | `3c` |
| `ecbp256` | 96 | `3c` |
| `ecbp384` | 144 | `3c` |
| `ecbp512` | 192 | `3c` |
| `ed25519` | 128 | — |

## HMAC keys

| Algorithm | Reported length | Formula |
| --- | ---: | --- |
| `hmac-sha1` | 128 | `2b` |
| `hmac-sha256` | 128 | `2b` |
| `hmac-sha384` | 256 | `2b` |
| `hmac-sha512` | 256 | `2b` |

## Symmetric keys

| Algorithm | Reported length | Formula |
| --- | ---: | --- |
| `aes128` | 16 | `k` |
| `aes192` | 24 | `k` |
| `aes256` | 32 | `k` |

## Wrap keys

| Algorithm | Reported length | Formula |
| --- | ---: | --- |
| `aes128-ccm-wrap` | 24 | `k + 8` |
| `aes192-ccm-wrap` | 32 | `k + 8` |
| `aes256-ccm-wrap` | 40 | `k + 8` |
| `rsa2048` | 904 | `7n / 2 + 8` |
| `rsa3072` | 1,352 | `7n / 2 + 8` |
| `rsa4096` | 1,800 | `7n / 2 + 8` |

## OTP AEAD keys

| Algorithm | Reported length | Formula |
| --- | ---: | --- |
| `aes128-yubico-otp` | 20 | `k + 4` |
| `aes192-yubico-otp` | 28 | `k + 4` |
| `aes256-yubico-otp` | 36 | `k + 4` |

## Public wrap keys

| Algorithm | Reported length | Formula |
| --- | ---: | --- |
| `rsa2048` | 264 | `n + 8` |
| `rsa3072` | 392 | `n + 8` |
| `rsa4096` | 520 | `n + 8` |
