#!/usr/bin/env ruby
# frozen_string_literal: true

# Convert a top-down 128x64 24-bit BMP into native SH1106/SSD1306 frames.
# Ordered dithering preserves the grayscale product rendering. Only the dark
# interior of the strap hole changes between the LED-off and LED-on frames.

unless ARGV.length == 5
  abort "usage: #{$PROGRAM_NAME} INPUT.bmp OFF.mono1 ON.mono1 OFF.pgm ON.pgm"
end

input_path, off_path, on_path, off_preview_path, on_preview_path = ARGV
bitmap = File.binread(input_path)
abort "input is not a BMP" unless bitmap.start_with?("BM")

pixel_offset = bitmap.byteslice(10, 4).unpack1("V")
width = bitmap.byteslice(18, 4).unpack1("l<")
height = bitmap.byteslice(22, 4).unpack1("l<")
bits_per_pixel = bitmap.byteslice(28, 2).unpack1("v")
compression = bitmap.byteslice(30, 4).unpack1("V")
abort "expected a top-down 128x64 bitmap" unless width == 128 && height == -64
abort "expected uncompressed 24-bit pixels" unless bits_per_pixel == 24 && compression.zero?

BAYER = [
  [0, 8, 2, 10],
  [12, 4, 14, 6],
  [3, 11, 1, 9],
  [15, 7, 13, 5]
].freeze

def pack_frame(pixels)
  frame = String.new(capacity: 128 * 8, encoding: Encoding::BINARY)
  frame << "\0" * (128 * 8)
  64.times do |y|
    128.times do |x|
      next unless pixels[y][x]

      page = y / 8
      offset = (7 - page) * 128 + (127 - x)
      frame.setbyte(offset, frame.getbyte(offset) | (1 << (7 - y % 8)))
    end
  end
  frame
end

def preview(pixels)
  bytes = pixels.flatten.map { |lit| lit ? 255 : 0 }.pack("C*")
  "P5\n128 64\n255\n" + bytes
end

off = Array.new(64) { Array.new(128, false) }
on = Array.new(64) { Array.new(128, false) }

64.times do |y|
  128.times do |x|
    offset = pixel_offset + (y * width + x) * 3
    blue, green, red = bitmap.byteslice(offset, 3).bytes
    intensity = (red * 54 + green * 183 + blue * 19) >> 8
    strap_hole = ((x - 38)**2 * 36) + ((y - 31)**2 * 9) <= 3**2 * 36
    off_intensity = strap_hole ? 0 : intensity
    on_intensity = strap_hole ? 255 : intensity

    threshold = BAYER[y % 4][x % 4] * 16 + 8
    off[y][x] = off_intensity > 44 && off_intensity >= threshold
    on[y][x] = on_intensity > 44 && on_intensity >= threshold
  end
end

File.binwrite(off_path, pack_frame(off))
File.binwrite(on_path, pack_frame(on))
File.binwrite(off_preview_path, preview(off))
File.binwrite(on_preview_path, preview(on))
