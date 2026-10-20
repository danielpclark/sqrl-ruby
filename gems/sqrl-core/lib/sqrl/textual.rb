# frozen_string_literal: true

module SQRL
  # The base56 "textual identity" format.
  #
  # The rescue (type 2) and previous-identity (type 3) blocks are treated as one
  # little-endian number and written in base56 (digits 2-9, upper-case letters without I
  # and O, lower-case letters without l and o). After every 19 characters a check
  # character is inserted: SHA-256(19 chars || line number) interpreted as a little-endian
  # number, modulo 56. For display the characters are grouped in fours, five groups per line.
  module Textual
    # The base56 alphabet.
    ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz".b.freeze
    CHARS_PER_LINE = 19
    LOG2_56 = 5.807_354_922_057_604
    INDEX = ALPHABET.each_byte.with_index.to_h.freeze
    private_constant :CHARS_PER_LINE, :LOG2_56, :INDEX

    module_function

    # Index of a byte in the alphabet, or nil.
    def alphabet_index(byte)
      INDEX[byte]
    end

    # Divide a little-endian big number (Array of bytes) in place by 56; returns the remainder.
    def divmod56!(num)
      rem = 0
      (num.length - 1).downto(0) do |i|
        cur = (rem << 8) | num[i]
        num[i] = cur / 56
        rem = cur % 56
      end
      rem
    end

    # Check character for one line of data characters.
    def check_char(line_chars, line)
      digest = Crypto.sha256(line_chars.pack("C*") + [line].pack("C"))
      rem = 0
      digest.bytes.reverse_each { |b| rem = ((rem << 8) | b) % 56 }
      ALPHABET.getbyte(rem)
    end

    # Encode bytes into the raw textual identity string (check characters included, no spacing).
    def encode(data)
      data = data.b
      expected_len = ((data.bytesize * 8) / LOG2_56).ceil
      num = data.bytes
      out = []
      line_chars = []
      line = 0
      expected_len.times do
        if line_chars.length == CHARS_PER_LINE
          out << check_char(line_chars, line)
          line_chars = []
          line = (line + 1) & 0xFF
        end
        c = num.all?(&:zero?) ? ALPHABET.getbyte(0) : ALPHABET.getbyte(divmod56!(num))
        out << c
        line_chars << c
      end
      out << check_char(line_chars, line)
      out.pack("C*").force_encoding("UTF-8")
    end

    # Format a raw textual identity for display: groups of four, five groups per line.
    def format_for_display(raw)
      out = +""
      raw.each_char.with_index do |c, i|
        if i.positive?
          if (i % 20).zero?
            out << "\n"
          elsif (i % 4).zero?
            out << " "
          end
        end
        out << c
      end
      out
    end

    # Decode a textual identity (whitespace and dashes are ignored) into the block bytes.
    # Raises FormatError naming the (1-based) line whose check character failed.
    def decode(text)
      cleaned = text.to_s.b.delete(" \t\r\n\f\v-").bytes
      raise FormatError, "empty textual identity" if cleaned.empty?

      cleaned.each do |c|
        raise FormatError, "invalid character '#{c.chr}' in textual identity" unless alphabet_index(c)
      end
      total = cleaned.length
      data_chars = []
      line_chars = []
      line = 0
      cleaned.each_with_index do |c, i|
        is_check = line_chars.length == CHARS_PER_LINE || i == total - 1
        if is_check
          raise FormatError, "check character mismatch on line #{line + 1}" unless c == check_char(line_chars, line)

          line_chars = []
          line = (line + 1) & 0xFF
        else
          data_chars << c
          line_chars << c
        end
      end
      expected_bytes = ((data_chars.length * LOG2_56) / 8.0).floor
      num = Array.new(expected_bytes + 2, 0)
      data_chars.reverse_each do |c|
        carry = alphabet_index(c)
        num.map! do |byte|
          cur = (byte * 56) + carry
          carry = cur >> 8
          cur & 0xFF
        end
        raise FormatError, "textual identity value out of range" unless carry.zero?
      end
      raise FormatError, "textual identity value out of range" if num[expected_bytes..].any? { |b| b != 0 }

      num.first(expected_bytes).pack("C*")
    end
  end
end
