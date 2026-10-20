# frozen_string_literal: true

RSpec.describe SQRL::URL do
  def b64(str) = SQRL::Util.b64u_encode(str)

  it "parses a basic URL" do
    u = described_class.parse("sqrl://WWW.Example.com/cli.sqrl?nut=abc123")
    expect(u.host).to eq("www.example.com")
    expect(u.site_key).to eq("www.example.com")
    expect(u.nut).to eq("abc123")
    expect(u.post_url).to eq("https://www.example.com/cli.sqrl?nut=abc123")
    expect(u.post_url_for_qry("/cli.sqrl?nut=def")).to eq("https://www.example.com/cli.sqrl?nut=def")
    expect { u.post_url_for_qry("https://evil.example/cli") }.to raise_error(SQRL::ProtocolError)
    expect { u.post_url_for_qry("//evil.example/cli") }.to raise_error(SQRL::ProtocolError)
    expect(u.original).to eq("sqrl://WWW.Example.com/cli.sqrl?nut=abc123")
    expect(u.to_s).to eq(u.original)
  end

  it "handles the path extension, port and user info" do
    u = described_class.parse("sqrl://user:pw@Example.com:8443/jimbo/cli.sqrl?x=6&nut=1")
    expect(u.authority).to eq("example.com:8443")
    expect(u.port).to eq(8443)
    expect(u.site_key).to eq("example.com/jimbo")
    expect(u.post_url).to eq("https://example.com:8443/jimbo/cli.sqrl?x=6&nut=1")

    # x larger than the path just takes the whole path
    expect(described_class.parse("sqrl://example.com/ab?x=99&nut=1").site_key).to eq("example.com/ab")
    # GRC's own example
    expect(described_class.parse("sqrl://www.grc.com/sqrl?x=5&nut=Na2MOglf7NyyupQ8-dtj1g").site_key)
      .to eq("www.grc.com/sqrl")
  end

  it "matches the examples from SQRL Operating Details" do
    {
      "sqrl://ExAmPlE.cOm/?nut=1" => "example.com",
      "sqrl://example.com:44344/?nut=1" => "example.com",
      "sqrl://jonny@example.com/?nut=1" => "example.com",
      "sqrl://Jonny:Secret@example.com/?nut=1" => "example.com",
      "sqrl://example.com/jimbo/?x=6&nut=1" => "example.com/jimbo",
      "sqrl://EXAMPLE.COM/JIMBO?x=16&nut=1" => "example.com/JIMBO",
      "sqrl://www.domain.com/sqrl?x=9999&nut=zingdoodle" => "www.domain.com/sqrl",
      "sqrl://example.com/abc?X=2&nut=1" => "example.com/a",
      "sqrl://example.com/abc?x=2z&nut=1" => "example.com/a",
      "sqrl://example.com/abc?x=0&nut=1" => "example.com"
    }.each do |url, site_key|
      expect(described_class.parse(url).site_key).to eq(site_key), url
    end
  end

  it "never cuts a multi-byte path character" do
    u = described_class.parse("sqrl://example.com/éabc?x=2&nut=1")
    expect(u.site_key).to eq("example.com/")
    u = described_class.parse("sqrl://example.com/éabc?x=3&nut=1")
    expect(u.site_key).to eq("example.com/é")
  end

  it "decodes the cancel URL" do
    u = described_class.parse("sqrl://example.com/cli.sqrl?nut=1&can=#{b64('https://example.com/cancelled')}")
    expect(u.cancel_url).to eq("https://example.com/cancelled")
    u = described_class.parse("sqrl://example.com/cli.sqrl?nut=1&can=#{b64('/login?cancel=1')}")
    expect(u.cancel_url).to eq("https://example.com/login?cancel=1")
    expect { described_class.parse("sqrl://example.com/cli.sqrl?nut=1&can=%%%") }.to raise_error(SQRL::FormatError)
  end

  it "accepts qrl:// only for loopback hosts" do
    u = described_class.parse("qrl://localhost:8080/cli.sqrl?nut=1")
    expect(u.post_url).to eq("http://localhost:8080/cli.sqrl?nut=1")
    expect(u.http_scheme).to eq("http")
    expect(described_class.parse("qrl://127.0.0.1/cli.sqrl?nut=1").origin).to eq("http://127.0.0.1")
    expect(described_class.parse("qrl://app.localhost/cli.sqrl?nut=1").origin).to eq("http://app.localhost")
    expect { described_class.parse("qrl://example.com/cli.sqrl?nut=1") }.to raise_error(SQRL::FormatError)
    expect { described_class.parse("https://example.com/cli.sqrl?nut=1") }.to raise_error(SQRL::FormatError)
    expect { described_class.parse("sqrl:///cli.sqrl") }.to raise_error(SQRL::FormatError)
    expect { described_class.parse("not a url") }.to raise_error(SQRL::FormatError)
    expect { described_class.parse(nil) }.to raise_error(SQRL::FormatError)
  end

  it "builds Alt-ID site keys and checks hosts" do
    u = described_class.parse("sqrl://example.com/cli.sqrl?nut=1")
    expect(u.site_key_bytes).to eq("example.com".b)
    expect(u.site_key_bytes("work")).to eq("example.com\0work".b)
    expect(u.site_key_bytes("  ")).to eq("example.com".b)
    expect(u.same_host?("https://EXAMPLE.com/loggedin?x=1")).to be(true)
    expect(u.same_host?("https://example.com:8443/")).to be(true)
    expect(u.same_host?("https://example.org/")).to be(false)
    expect(u.same_host?("javascript:alert(1)")).to be(false)
    expect(u.same_host?("https://user@example.com/x")).to be(true)
    # a sqrl:// site must not be downgraded to plain http
    expect(u.same_host?("http://example.com/loggedin")).to be(false)
    expect(u.resolve("/x")).to eq("https://example.com/x")
    expect(u.resolve("x")).to eq("https://example.com/x")
    expect(u.resolve("http://other.example/x")).to eq("http://other.example/x")
  end

  it "parses IPv6 authorities" do
    u = described_class.parse("sqrl://[2001:db8::1]:444/cli.sqrl?nut=1")
    expect(u.host).to eq("[2001:db8::1]")
    expect(u.port).to eq(444)
    expect(u.site_key).to eq("[2001:db8::1]")
    expect(described_class.parse("sqrl://[2001:db8::1]/?nut=1").port).to be_nil
    expect { described_class.parse("sqrl://[2001:db8::1/?nut=1") }.to raise_error(SQRL::FormatError)
    expect { described_class.parse("sqrl://example.com:abc/?nut=1") }.to raise_error(SQRL::FormatError)
  end

  it "defaults the path and drops fragments" do
    u = described_class.parse("sqrl://example.com?nut=1#frag")
    expect(u.path).to eq("/")
    expect(u.query).to eq("nut=1")
    expect(u.post_url).to eq("https://example.com/?nut=1")
  end

  describe ".query_pairs" do
    it "splits and percent-decodes values" do
      expect(described_class.query_pairs("nut=a%2Fb&x=5&flag&=v")).to eq([%w[nut a/b], %w[x 5], ["flag", ""], ["", "v"]])
      expect(described_class.query_pairs("")).to eq([])
      expect(described_class.query_pairs("a=%zz")).to eq([["a", "%zz"]])
    end
  end

  it "is a value object" do
    a = described_class.parse("sqrl://example.com/?nut=1")
    b = described_class.parse("sqrl://example.com/?nut=1")
    expect(a).to eq(b)
    expect(a.hash).to eq(b.hash)
    expect(a).to be_frozen
  end
end
