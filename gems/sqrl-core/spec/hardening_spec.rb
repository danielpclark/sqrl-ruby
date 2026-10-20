# frozen_string_literal: true

RSpec.describe "server hardening options" do
  describe SQRL::URL do
    it "treats only real loopback addresses as loopback" do
      %w[localhost app.localhost 127.0.0.1 127.1.2.3 [::1] ::1 [::ffff:127.0.0.1]].each do |h|
        expect(described_class.loopback?(h)).to be(true), h
      end
      %w[example.com 128.0.0.1 [2001:db8::1] [::2] 127.0.0.1.evil.com localhost.evil.com].each do |h|
        expect(described_class.loopback?(h)).to be(false), h
      end
      expect(described_class.parse("qrl://[::1]:8080/cli.sqrl?nut=1").origin).to eq("http://[::1]:8080")
      expect { described_class.parse("qrl://[2001:db8::1]/cli.sqrl?nut=1") }.to raise_error(SQRL::FormatError)
    end
  end

  describe SQRL::Server::Config do
    it "allows qrl only for loopback hosts, including bracketed IPv6 loopback" do
      expect(described_class.new(host: "[::1]:9000", scheme: "qrl").origin).to eq("http://[::1]:9000")
      expect(described_class.new(host: "127.0.0.1:9000", scheme: "qrl").bare_host).to eq("127.0.0.1")
      expect { described_class.new(host: "[2001:db8::1]:9000", scheme: "qrl") }.to raise_error(ArgumentError, /loopback/)
    end

    it "validates allowed_hosts, prune_every and the hooks" do
      expect { described_class.new(host: "e.com", allowed_hosts: "e.com") }.to raise_error(ArgumentError, /allowed_hosts/)
      expect { described_class.new(host: "e.com", allowed_hosts: [1]) }.to raise_error(ArgumentError, /allowed_hosts/)
      expect { described_class.new(host: "e.com", prune_every: 0) }.to raise_error(ArgumentError, /prune_every/)
      expect { described_class.new(host: "e.com", before_issue: 1) }.to raise_error(ArgumentError, /before_issue/)
      expect { described_class.new(host: "e.com", before_handle: 1) }.to raise_error(ArgumentError, /before_handle/)
      c = described_class.new(host: "e.com", prune_every: nil)
      expect(c.prune_every).to be_nil
      expect(described_class.new(host: "e.com").prune_every).to eq(1000)
    end

    it "matches allowed_hosts by exact string (with or without port) or regexp" do
      c = described_class.new(host: "e.com", allowed_hosts: ["Example.com", "app.example.com:8443", /\A[a-z]+\.tenants\.example\z/])
      expect(c.host_allowed?("example.com")).to be(true)
      expect(c.host_allowed?("EXAMPLE.com:443")).to be(true)
      expect(c.host_allowed?("app.example.com:8443")).to be(true)
      expect(c.host_allowed?("app.example.com")).to be(false)
      expect(c.host_allowed?("acme.tenants.example")).to be(true)
      expect(c.host_allowed?("evil.example")).to be(false)
      expect(described_class.new(host: "e.com").host_allowed?("anything.example")).to be(true)
    end
  end

  describe "hooks and pruning" do
    it "runs before_issue and before_handle with their contexts and surfaces RateLimited" do
      seen = []
      handler = new_handler(before_issue: ->(ctx) { seen << [:issue, ctx[:ip], ctx[:pending_login_id]] },
                            before_handle: ->(ctx) { seen << [:handle, ctx[:phase], ctx[:ip], ctx[:command]] })
      login_id, s = new_session(handler, identity(21))
      exchange(handler, s, s.query)
      expect(seen).to include([:issue, FlowHelpers::IP, login_id],
                              [:handle, :request, FlowHelpers::IP, nil],
                              [:handle, :command, FlowHelpers::IP, :query])

      limited = new_handler(before_handle: lambda { |ctx|
        raise SQRL::Server::RateLimited.new("slow down", retry_after: 7) if ctx[:phase] == :request
      })
      _, s = new_session(limited, identity(22))
      expect { post(limited, s.query) }.to raise_error(SQRL::Server::RateLimited) { |e| expect(e.retry_after).to eq(7) }
      expect(limited.stores.nuts.size).to eq(1), "the nut was not consumed when the hook refused early"

      refusing = new_handler(before_issue: ->(_ctx) { raise SQRL::Server::RateLimited })
      expect { refusing.new_login_url(ip: "1.2.3.4") }.to raise_error(SQRL::Server::RateLimited)
      expect(refusing.stores.pending_logins.size).to eq(0)
    end

    it "prunes expired state every prune_every requests" do
      now = Time.at(1_700_000_000)
      handler = new_handler(prune_every: 3, nut_ttl: 10, clock: -> { now })
      3.times { handler.new_login_url(ip: "1.2.3.4") } # 3 requests: prune runs, nothing expired yet
      expect(handler.stores.nuts.size).to eq(3)
      now += 60
      handler.new_login_url(ip: "1.2.3.4") # request 4: no prune
      expect(handler.stores.nuts.size).to eq(4)
      handler.new_login_url(ip: "1.2.3.4") # request 5
      handler.new_login_url(ip: "1.2.3.4") # request 6: prune removes the three expired nuts
      expect(handler.stores.nuts.size).to eq(3)
      expect(handler.stores.pending_logins.size).to eq(3)

      never = new_handler(prune_every: nil, nut_ttl: 10, clock: -> { now })
      5.times { never.new_login_url(ip: "1.2.3.4") }
      now += 60
      5.times { never.new_login_url(ip: "1.2.3.4") }
      expect(never.stores.nuts.size).to eq(10)
    end
  end
end
