#!/usr/bin/env ruby
# frozen_string_literal: true

# Convert a top-down 240x240 BGRA bitmap into the two big-endian RGB565
# ST7789 frames. Only the dark interior of the strap hole changes: black when
# the YubiHSM LED is off and green when it is on.

unless ARGV.length == 5
  abort "usage: #{$PROGRAM_NAME} INPUT.bmp OFF.rgb565 ON.rgb565 OFF.ppm ON.ppm"
end

input_path, off_path, on_path, off_preview_path, on_preview_path = ARGV
bitmap = File.binread(input_path)
abort "input is not a BMP" unless bitmap.start_with?("BM")

pixel_offset = bitmap.byteslice(10, 4).unpack1("V")
width = bitmap.byteslice(18, 4).unpack1("l<")
height = bitmap.byteslice(22, 4).unpack1("l<")
bits_per_pixel = bitmap.byteslice(28, 2).unpack1("v")
compression = bitmap.byteslice(30, 4).unpack1("V")
abort "expected a top-down 240x240 BGRA bitmap" unless width == 240 && height == -240
abort "expected a 32-bit bitfields bitmap" unless bits_per_pixel == 32 && compression == 3

off = String.new(capacity: width * -height * 2, encoding: Encoding::BINARY)
on = String.new(capacity: width * -height * 2, encoding: Encoding::BINARY)
off_rgb = String.new(capacity: width * -height * 3, encoding: Encoding::BINARY)
on_rgb = String.new(capacity: width * -height * 3, encoding: Encoding::BINARY)

(-height).times do |y|
  width.times do |x|
    offset = pixel_offset + (y * width + x) * 4
    blue, green, red, = bitmap.byteslice(offset, 4).bytes

    ellipse = ((x - 120)**2 * 49) + ((y - 46)**2 * 256) <= 16**2 * 49
    strap_hole = ellipse && red < 70 && green < 70 && blue < 70
    off_red, off_green, off_blue = strap_hole ? [0, 0, 0] : [red, green, blue]
    on_red, on_green, on_blue = strap_hole ? [24, 255, 72] : [red, green, blue]

    off << [((off_red >> 3) << 11) | ((off_green >> 2) << 5) | (off_blue >> 3)].pack("n")
    on << [((on_red >> 3) << 11) | ((on_green >> 2) << 5) | (on_blue >> 3)].pack("n")
    off_rgb << off_red.chr << off_green.chr << off_blue.chr
    on_rgb << on_red.chr << on_green.chr << on_blue.chr
  end
end

File.binwrite(off_path, off)
File.binwrite(on_path, on)
File.binwrite(off_preview_path, "P6\n#{width} #{-height}\n255\n" + off_rgb)
File.binwrite(on_preview_path, "P6\n#{width} #{-height}\n255\n" + on_rgb)
