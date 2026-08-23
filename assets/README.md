# YubiHSM display frames

`yubihsm-source.png` is a display-oriented rendering derived from Yubico's
public front product image for the YubiHSM 2, downloaded from the official
[YubiHSM 2 product page](https://www.yubico.com/product/yubihsm-2/) on
2026-08-24 and reframed with OpenAI image generation. Yubico owns the YubiHSM
and Yubico marks; those marks are not covered by this repository's MIT or
Apache-2.0 code licenses.

The two 240x240 previews place the product over the same charcoal background
used by `virtual-yubikey`. Their matching `.rgb565` files are complete
115,200-byte, big-endian RGB565 ST7789 frames. The frames are identical except
for the LED inside the strap hole:

- `yubihsm-led-off` renders the strap hole black;
- `yubihsm-led-on` renders only its dark interior green.

The worker includes the native frames directly, so the deployed Pi does not
decode or transform images at runtime. To rebuild them on macOS:

```sh
sips -s format bmp assets/yubihsm-source.png --out /tmp/yubihsm-source.bmp
ruby scripts/build_yubihsm_display_assets.rb \
  /tmp/yubihsm-source.bmp \
  assets/yubihsm-led-off.rgb565 assets/yubihsm-led-on.rgb565 \
  /tmp/yubihsm-led-off.ppm /tmp/yubihsm-led-on.ppm
sips -s format png /tmp/yubihsm-led-off.ppm --out assets/yubihsm-led-off.png
sips -s format png /tmp/yubihsm-led-on.ppm --out assets/yubihsm-led-on.png
```
