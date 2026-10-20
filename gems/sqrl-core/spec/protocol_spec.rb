# frozen_string_literal: true

RSpec.describe SQRL::Protocol do
  def b64(str) = SQRL::Util.b64u_encode(str)

  describe SQRL::Tif do
    it "parses hex and exposes predicates" do
      t = described_class.parse("5")
      expect(t).to be_id_match
      expect(t).to be_ips_matched
      expect(t).not_to be_previous_id_match
      expect(described_class.new(0x2c0).to_hex).to eq("2c0")
      expect { described_class.parse("zz") }.to raise_error(SQRL::FormatError)
      expect { described_class.parse("") }.to raise_error(SQRL::FormatError)
      expect(described_class.new(SQRL::Tif::COMMAND_FAILED)).to be_error
      expect(described_class.new(SQRL::Tif::ID_MATCH | SQRL::Tif::SQRL_DISABLED)).not_to be_error
    end

    it "knows which bits are defined" do
      expect(described_class.new(0x3ff)).to be_defined
      expect(described_class.new(0x400)).not_to be_defined
      expect(described_class.parse("405")).not_to be_defined
    end

    it "is an immutable value object" do
      t = described_class.new(1)
      expect(t | SQRL::Tif::IPS_MATCHED).to eq(described_class.new(5))
      expect(t).to eq(described_class.new(1))
      expect(t).to eq(1)
      expect(t.without(1).value).to eq(0)
      expect(t).to be_frozen
      expect(described_class[t]).to be(t)
    end
  end

  describe SQRL::Command do
    it "parses and renders" do
      expect(described_class.parse("query")).to eq(:query)
      expect(described_class.parse("nope")).to be_nil
      expect(described_class.parse(nil)).to be_nil
      expect(described_class.to_wire(:ident)).to eq("ident")
      expect { described_class.to_wire(:bogus) }.to raise_error(ArgumentError)
    end
  end

  describe SQRL::ClientOptions do
    it "round-trips the wire form" do
      o = described_class.new(sqrlonly: true, cps: true)
      expect(o.to_wire).to eq("sqrlonly~cps")
      expect(described_class.from_wire("cps~suk~noiptest")).to eq(described_class.new(cps: true, suk: true,
                                                                                      noiptest: true))
      expect(described_class.new.to_wire).to be_nil
      expect(described_class.from_wire("bogus~cps").to_wire).to eq("cps")
      expect(described_class.from_wire(nil)).to eq(described_class.new)
    end

    it "copies independently" do
      a = described_class.new(cps: true)
      b = a.dup
      b.cps = false
      expect(a).to be_cps
    end
  end

  describe SQRL::Ask do
    it "round-trips" do
      ask = described_class.new(message: "Delete everything?",
                                buttons: [{ label: "Yes", url: "https://example.com/yes" }, { label: "No" }])
      wire = ask.to_wire
      expect(wire).to start_with("RGVsZXRlIGV2ZXJ5dGhpbmc_~")
      expect(described_class.parse(wire)).to eq(ask)
      simple = described_class.parse(b64("Hello"))
      expect(simple.message).to eq("Hello")
      expect(simple.buttons).to be_empty
    end

    it "keeps at most two buttons and rejects bad text" do
      wire = [b64("m"), b64("a"), b64("b"), b64("c")].join("~")
      expect(described_class.parse(wire).buttons.map(&:label)).to eq(%w[a b])
      expect { described_class.parse("%%%") }.to raise_error(SQRL::FormatError)
    end
  end

  describe ".parse_pairs" do
    it "parses CRLF and LF lists" do
      expect(described_class.parse_pairs("a=1\r\nb=2\n\nc\r\n")).to eq([%w[a 1], %w[b 2], ["c", ""]])
      expect(described_class.parse_pairs("k=v=w")).to eq([["k", "v=w"]])
      expect(described_class.parse_pairs(nil)).to eq([])
    end
  end

  describe ".version_supported?" do
    it "handles lists and ranges" do
      expect(described_class.version_supported?("1", 1)).to be(true)
      expect(described_class.version_supported?("1,2", 1)).to be(true)
      expect(described_class.version_supported?("1-3", 2)).to be(true)
      expect(described_class.version_supported?("2", 1)).to be(false)
      expect(described_class.version_supported?("2-4,6", 1)).to be(false)
      expect(described_class.version_supported?("x", 1)).to be(false)
      expect(described_class.version_supported?(nil, 1)).to be(false)
      expect(described_class.version_supported?(" 1 , 5-7 ", 6)).to be(true)
    end
  end

  describe SQRL::ServerResponse do
    it "parses a response" do
      text = "ver=1\r\nnut=abc\r\ntif=5\r\nqry=/cli.sqrl?nut=abc\r\nsin=0\r\n"
      r = described_class.parse(b64(text))
      expect(r.nut).to eq("abc")
      expect(r.tif).to eq(SQRL::Tif.new(5))
      expect(r.sin).to eq("0")
      expect(r.suk).to be_nil
      expect(r.url).to be_nil
      expect(r["qry"]).to eq("/cli.sqrl?nut=abc")
      expect(r.raw).to eq(b64(text))
    end

    it "strips whitespace from the raw body but keeps it verbatim otherwise" do
      text = "ver=1\r\nnut=abc\r\ntif=5\r\nqry=/x\r\n"
      r = described_class.parse(" #{b64(text)}\n")
      expect(r.raw).to eq(b64(text))
    end

    it "decodes suk and ask" do
      suk = "\x09" * 32
      ask = SQRL::Ask.new(message: "Hi").to_wire
      r = described_class.parse(b64("ver=1\r\nnut=a\r\ntif=1\r\nqry=/x\r\nsuk=#{b64(suk)}\r\nask=#{ask}\r\nurl=https://example.com/ok\r\ncan=/bye\r\n"))
      expect(r.suk).to eq(suk)
      expect(r.ask.message).to eq("Hi")
      expect(r.url).to eq("https://example.com/ok")
      expect(r.can).to eq("/bye")
      expect { described_class.parse(b64("ver=1\r\nnut=a\r\ntif=1\r\nqry=/x\r\nsuk=#{b64("short")}\r\n")) }
        .to raise_error(SQRL::FormatError)
    end

    it "rejects unsupported versions, missing fields and undefined TIF bits" do
      bad = -> { described_class.parse(b64("ver=2\r\nnut=a\r\ntif=0\r\nqry=/x\r\n")) }
      expect(&bad).to raise_error(SQRL::ProtocolError, /version/)
      expect { described_class.parse(b64("ver=1\r\ntif=0\r\nqry=/x\r\n")) }.to raise_error(SQRL::ProtocolError, /nut/)
      expect do
        described_class.parse(b64("ver=1\r\nnut=\r\ntif=0\r\nqry=/x\r\n"))
      end.to raise_error(SQRL::ProtocolError, /empty nut/)
      expect { described_class.parse(b64("ver=1\r\nnut=a\r\nqry=/x\r\n")) }.to raise_error(SQRL::ProtocolError, /tif/)
      expect { described_class.parse(b64("ver=1\r\nnut=a\r\ntif=0\r\n")) }.to raise_error(SQRL::ProtocolError, /qry/)
      expect { described_class.parse(b64("ver=1\r\nnut=a\r\ntif=405\r\nqry=/x\r\n")) }
        .to raise_error(SQRL::ProtocolError, /undefined TIF/)
      expect { described_class.parse("") }.to raise_error(SQRL::ProtocolError, /empty/)
      expect { described_class.parse(b64("\xff\xfe".b)) }.to raise_error(SQRL::ProtocolError, /UTF-8/)
    end
  end
end
