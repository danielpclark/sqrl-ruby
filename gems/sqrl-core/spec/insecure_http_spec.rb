# frozen_string_literal: true

require "logger"
require "stringio"

RSpec.describe "insecure_http testing mode" do
  let(:identity) { SQRL::UnlockedIdentity.from_iuk("\x11" * 32) }

  describe SQRL::Server::Config do
    before { described_class.reset_warnings! }

    it "issues sqrl:// by default, whatever the host" do
      expect(described_class.new(host: "localhost:3000").scheme).to eq("sqrl")
      expect(described_class.new(host: "localhost:3000").origin).to eq("https://localhost:3000")
      expect(described_class.new(host: "example.com").insecure_http?).to be(false)
    end

    it "issues qrl:// only when insecure_http is set, for loopback hosts, warning once" do
      log = StringIO.new
      config = described_class.new(host: "localhost:3000", insecure_http: true, logger: Logger.new(log))
      expect(config.scheme).to eq("qrl")
      expect(config.origin).to eq("http://localhost:3000")
      expect(config.insecure_http?).to be(true)
      described_class.new(host: "127.0.0.1:3000", insecure_http: true, logger: Logger.new(log))
      expect(log.string.scan("loopback-only testing mode").size).to eq(1)
    end

    it "refuses insecure_http for any host that is not loopback" do
      expect { described_class.new(host: "example.com", insecure_http: true) }
        .to raise_error(ArgumentError, /loopback/)
      expect { described_class.new(host: "[2001:db8::1]:3000", insecure_http: true) }
        .to raise_error(ArgumentError, /loopback/)
      # scheme: "qrl" is the same mode spelled the old way
      expect { described_class.new(host: "example.com", scheme: "qrl") }.to raise_error(ArgumentError, /loopback/)
      expect(described_class.new(host: "localhost", scheme: "qrl").insecure_http?).to be(true)
    end
  end

  describe SQRL::Session do
    it "refuses qrl:// URLs unless insecure: true" do
      url = "qrl://localhost:8080/cli.sqrl?nut=n1"
      expect { described_class.new(identity, url) }.to raise_error(SQRL::ProtocolError, /insecure: true/)
      session = described_class.new(identity, url, insecure: true)
      expect(session).to be_insecure
      expect(session.query.url).to start_with("http://localhost:8080/cli.sqrl")
    end

    it "never accepts qrl:// for a non-loopback host, even when insecure" do
      expect { described_class.new(identity, "qrl://example.com/cli?nut=1", insecure: true) }
        .to raise_error(SQRL::FormatError)
    end
  end
end
