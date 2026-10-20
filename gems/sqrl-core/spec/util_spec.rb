# frozen_string_literal: true

RSpec.describe SQRL::Util do
  describe "base64url" do
    it "round-trips without padding or URL-unsafe characters" do
      data = [0, 1, 2, 250, 251, 252, 253, 254, 255].pack("C*")
      enc = described_class.b64u_encode(data)
      expect(enc).not_to include("=", "+", "/")
      expect(described_class.b64u_decode(enc)).to eq(data)
    end

    it "tolerates whitespace and padding when decoding" do
      expect(described_class.b64u_decode(" AAEC\n -vv8 _f7_ == ").bytes).to eq([0, 1, 2, 250, 251, 252, 253, 254, 255])
    end

    it "rejects invalid input" do
      expect { described_class.b64u_decode("a") }.to raise_error(SQRL::FormatError)
      expect { described_class.b64u_decode("ab+c") }.to raise_error(SQRL::FormatError)
      expect { described_class.b64u_decode(nil) }.to raise_error(SQRL::FormatError)
    end

    it "decodes fixed sizes" do
      expect(described_class.b64u_decode_fixed("AAEC", 3).bytesize).to eq(3)
      expect { described_class.b64u_decode_fixed("AAEC", 4) }.to raise_error(SQRL::FormatError, /expected 4 bytes/)
    end

    it "returns binary-encoded strings" do
      expect(described_class.b64u_decode("AAEC").encoding).to eq(Encoding::BINARY)
    end
  end

  describe "hex" do
    it "round-trips" do
      expect(described_class.hex_decode("00ff10Ab").bytes).to eq([0, 255, 16, 171])
      expect(described_class.hex_encode([0, 255, 16, 171].pack("C*"))).to eq("00ff10ab")
    end

    it "rejects odd lengths and bad characters" do
      expect { described_class.hex_decode("abc") }.to raise_error(SQRL::FormatError)
      expect { described_class.hex_decode("zz") }.to raise_error(SQRL::FormatError)
    end
  end

  describe "little-endian helpers" do
    it "packs and unpacks" do
      expect(described_class.le_u16("\x34\x12".b)).to eq(0x1234)
      expect(described_class.le_u32("\x78\x56\x34\x12".b)).to eq(0x12345678)
      expect(described_class.pack_le_u16(0x1234)).to eq("\x34\x12".b)
      expect(described_class.pack_le_u32(0x12345678)).to eq("\x78\x56\x34\x12".b)
      expect(described_class.le_u16("\xFF\x34\x12".b, 1)).to eq(0x1234)
    end
  end

  describe ".xor" do
    it "xors equal-length strings" do
      expect(described_class.xor("\x0F\xF0".b, "\xFF\xFF".b)).to eq("\xF0\x0F".b)
      expect { described_class.xor("a", "bb") }.to raise_error(ArgumentError)
    end
  end

  describe ".secure_compare" do
    it "compares byte strings" do
      expect(described_class.secure_compare("abc", "abc")).to be(true)
      expect(described_class.secure_compare("abc", "abd")).to be(false)
      expect(described_class.secure_compare("abc", "ab")).to be(false)
      expect(described_class.secure_compare(nil, "ab")).to be(false)
    end
  end

  describe ".random_bytes" do
    it "returns the requested number of bytes" do
      expect(described_class.random_bytes(16).bytesize).to eq(16)
      expect(described_class.random_bytes(16)).not_to eq(described_class.random_bytes(16))
    end
  end

  describe ".wipe" do
    it "clears a mutable string and leaves frozen ones alone" do
      s = +"secret"
      described_class.wipe(s)
      expect(s).to eq("")
      expect { described_class.wipe("frozen") }.not_to raise_error
    end
  end
end
