# Device storage capacity

`DeviceConfig::default()` enforces 256 persistent object records and 1,024 pages
of 126 bytes. Each object occupies one record and its validated `GetObjectInfo`
length rounded up to whole pages, with a minimum of one page. The factory
authentication key consumes one record and one page. `GET STORAGE INFO` uses
the same accounting as admission checks.

The page granularity was verified with physical opaque objects of 1, 125, 126,
127, 166, 206, 251, 252 and 253 bytes on firmware 2.4.1. Existing inventories on
two firmware-2.5.0 devices also exactly matched summed rounded object lengths.
The [measurement record](https://github.com/qpernil/pkcs11rs/blob/master/docs/yubihsm-storage-qualification.json)
includes restoration checks. Yubico documents the counters in
[GET STORAGE INFO](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html#get-storage-info-command).

Reported RSA lengths of 896, 1,344 and 1,792 bytes occupy 8, 11 and 15 pages,
respectively. With one authentication key, this reproduces the published
127 RSA-2048, 93 RSA-3072 and 68 RSA-4096 key capacities. These sizes describe
device storage, not host key encodings or Rust heap usage. Virtual-only PQC
algorithms use their documented logical object lengths and make no claim of
physical YubiHSM PQC capacity.

Protocol creation/import, opaque replacement, and trusted provisioning check
both limits before changing objects or sequence history. Replacement charges
only the difference from the old object's allocation. A rejected operation
returns `STORAGE_FAILED` (`0x07`) and preserves the existing object. Deletion
and shrinking immediately reclaim pages. Restoring a state image larger than
the configured capacity fails without resetting or discarding its objects.

## Explicit unlimited mode

Set `DeviceConfig.unlimited_storage = true` to disable both admission limits.
The field defaults to false, including when omitted from serialized config.
Frontends expose the same choice:

- USB worker: `--unlimited-storage`.
- I2C worker: `--unlimited-storage`.
- pkcs11rs connector: `--virtual-yubihsm-unlimited-storage` for all configured
  embedded HSMs.

Unlimited mode reports 65,535 nominal records and pages in the 16-bit storage
counters, with free counts saturating at zero; these counters do not impose
an admission ceiling in that mode. Runtime configuration controls the mode,
including on state restoration; a stored image does not silently enable it.

## Verification

`cargo test --locked -p virtual-yubihsm-core storage_` exercises physical page
boundaries, independent object/page exhaustion, unchanged state after rejected
creation or growth, capacity recovery, provisioning/restoration checks, and
the explicit unlimited opt-out. The downstream pkcs11rs capacity tests count
native and metadata objects through the real protocol core and exercise
metadata-creation failure and cleanup.
