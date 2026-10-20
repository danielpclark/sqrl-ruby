# frozen_string_literal: true

require "sqrl/test_vectors"

RSpec.describe SQRL::Textual do
  let(:log2_56) { 5.807_354_922_057_604 }

  it "has a well-formed alphabet" do
    expect(described_class::ALPHABET.bytesize).to eq(56)
    "01IOlo".each_byte { |b| expect(described_class.alphabet_index(b)).to be_nil }
    expect(described_class::ALPHABET.bytes.uniq.length).to eq(56)
  end

  it "round-trips various lengths, with and without display formatting" do
    [1, 2, 19, 20, 73, 127, 159, 191, 223].each do |len|
      data = SQRL::Util.random_bytes(len)
      enc = described_class.encode(data)
      chars = ((len * 8) / log2_56).ceil
      expect(enc.length).to eq(chars + chars.fdiv(19).ceil)
      expect(described_class.decode(enc)).to eq(data), "len #{len}"
      expect(described_class.decode(described_class.format_for_display(enc))).to eq(data)
    end
  end

  it "preserves leading and all-zero bytes" do
    data = [0, 0, 0, 5, 0, 0, 0, 0].pack("C*")
    expect(described_class.decode(described_class.encode(data))).to eq(data)
    zeros = "\0" * 73
    expect(described_class.decode(described_class.encode(zeros))).to eq(zeros)
  end

  it "catches typos with the check characters and names the line" do
    enc = described_class.encode("\x07" * 73)
    bytes = enc.bytes
    bytes[0], bytes[1] = bytes[1], bytes[0]
    expect { described_class.decode(bytes.pack("C*")) }.to raise_error(SQRL::FormatError, /line 1/)
  end

  it "rejects characters outside the alphabet and empty input" do
    expect { described_class.decode("22Y0") }.to raise_error(SQRL::FormatError, /invalid character '0'/)
    expect { described_class.decode(" - ") }.to raise_error(SQRL::FormatError, /empty/)
  end

  it "validates the Android sample" do
    bytes = described_class.decode(SQRL::TestVectors::ANDROID_TEXTUAL)
    expect(bytes.bytesize).to eq(73)
    expect(bytes.bytes.first(4)).to eq([73, 0, 2, 0])
    expect(described_class.decode(described_class.encode(bytes))).to eq(bytes)
  end

  it "formats for display in groups of four, five per line" do
    raw = (0...45).map { |i| described_class::ALPHABET[i % 56] }.join
    lines = described_class.format_for_display(raw).lines(chomp: true)
    expect(lines.length).to eq(3)
    expect(lines[0].length).to eq(24)
    expect(lines[0].split(" ").length).to eq(5)
  end

  describe "base56 vectors validated against GRC's client" do
    SQRL::TestVectors::BASE56_SHORT.each do |hex, expected|
      it "encodes #{hex} as #{expected}" do
        expect(described_class.encode(SQRL::Util.hex_decode(hex))).to eq(expected)
        expect(SQRL::Util.hex_encode(described_class.decode(expected)).upcase).to eq(hex)
      end
    end

    it "encodes the 80-byte example over six lines" do
      raw = described_class.encode(SQRL::Util.hex_decode(SQRL::TestVectors::BASE56_80_HEX))
      expect(described_class.format_for_display(raw)).to eq(SQRL::TestVectors::BASE56_80_TEXT)
      expect(SQRL::Util.hex_encode(described_class.decode(SQRL::TestVectors::BASE56_80_TEXT)).upcase)
        .to eq(SQRL::TestVectors::BASE56_80_HEX)
    end

    it "encodes the 87 random bytes example" do
      raw = described_class.encode(SQRL::Util.hex_decode(SQRL::TestVectors::BASE56_87_HEX))
      expect(described_class.format_for_display(raw)).to eq(SQRL::TestVectors::BASE56_87_TEXT)
      expect(SQRL::Util.hex_encode(described_class.decode(SQRL::TestVectors::BASE56_87_TEXT)).upcase)
        .to eq(SQRL::TestVectors::BASE56_87_HEX)
    end
  end
end
