# frozen_string_literal: true

require "openssl"
require "securerandom"

module SQRL
  # Small helpers: base64url (no padding), hex, random bytes, little-endian integers,
  # constant-time comparison and best-effort wiping of secret strings.
  module Util
    module_function

    # Encode bytes as base64url without padding (the only base64 variant SQRL uses).
    def b64u_encode(data)
      [data].pack("m0").tr("+/", "-_").delete("=")
    end

    # Decode base64url. Padding characters and ASCII whitespace are tolerated and ignored,
    # as the SQRL storage spec requires for the textual +SQRLDATA+ form.
    def b64u_decode(text)
      raise FormatError, "invalid base64url: not a string" unless text.is_a?(String)

      cleaned = text.delete(" \t\r\n\f\v=")
      raise FormatError, "invalid base64url: bad characters" unless cleaned.match?(/\A[A-Za-z0-9_-]*\z/)
      raise FormatError, "invalid base64url: bad length" if (cleaned.length % 4) == 1

      padded = cleaned.tr("-_", "+/")
      padded += "=" * ((4 - (padded.length % 4)) % 4)
      padded.unpack1("m0").b
    rescue ArgumentError => e
      raise FormatError, "invalid base64url: #{e.message}"
    end

    # Decode base64url into exactly +size+ bytes.
    def b64u_decode_fixed(text, size)
      bytes = b64u_decode(text)
      raise FormatError, "expected #{size} bytes, got #{bytes.bytesize}" unless bytes.bytesize == size

      bytes
    end

    # Lower-case hex encoding.
    def hex_encode(data)
      data.unpack1("H*")
    end

    # Hex decoding (case-insensitive, whitespace ignored).
    def hex_decode(text)
      cleaned = text.delete(" \t\r\n\f\v")
      raise FormatError, "odd-length hex string" if cleaned.length.odd?
      raise FormatError, "bad hex" unless cleaned.match?(/\A[0-9a-fA-F]*\z/)

      [cleaned].pack("H*")
    end

    # +n+ cryptographically secure random bytes.
    def random_bytes(n)
      SecureRandom.random_bytes(n)
    end

    def le_u16(bytes, offset = 0)
      bytes.byteslice(offset, 2).unpack1("v")
    end

    def le_u32(bytes, offset = 0)
      bytes.byteslice(offset, 4).unpack1("V")
    end

    def pack_le_u16(value)
      [value].pack("v")
    end

    def pack_le_u32(value)
      [value].pack("V")
    end

    # XOR two equal-length byte strings, returning a new binary string.
    def xor(a, b)
      raise ArgumentError, "xor length mismatch" unless a.bytesize == b.bytesize

      a.bytes.zip(b.bytes).map { |x, y| x ^ y }.pack("C*")
    end

    # Constant-time equality for two byte strings (false when the lengths differ).
    def secure_compare(a, b)
      return false unless a.is_a?(String) && b.is_a?(String) && a.bytesize == b.bytesize

      OpenSSL.fixed_length_secure_compare(a, b)
    end

    # Best-effort wipe of a mutable String holding secret material. Ruby cannot guarantee
    # that no copies remain; this merely shortens the window for the buffer we own.
    def wipe(str)
      return str unless str.is_a?(String) && !str.frozen?

      str.replace("\0" * str.bytesize)
      str.clear
    end

    # Force a binary-encoded copy of a string without mutating the argument.
    def binary(str)
      str.b
    end
  end
end
