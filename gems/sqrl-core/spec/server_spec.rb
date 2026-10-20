# frozen_string_literal: true

require_relative "support/flow_helpers"

RSpec.describe SQRL::Server do
  def b64(str) = SQRL::Util.b64u_encode(str)

  describe SQRL::Server::Config do
    it "applies defaults" do
      c = described_class.new(host: "example.com")
      expect(c.path).to eq("/sqrl/cli")
      expect(c.scheme).to eq("sqrl")
      expect(c.nut_ttl).to eq(300)
      expect(c.cps_token_ttl).to eq(60)
      expect(c).to be_require_ip_match
      expect(c.on_unknown_identity).to eq(:create)
      expect(c.origin).to eq("https://example.com")
      expect(c.cps_url_for("tok", nil)).to eq("https://example.com/sqrl/callback?t=tok")
      expect(c.now).to be_a(Time)
    end

    it "yields itself for block configuration" do
      c = described_class.new(host: "example.com") { |x| x.on_unknown_identity = :refuse }
      expect(c.on_unknown_identity).to eq(:refuse)
    end

    it "validates its values" do
      expect { described_class.new }.to raise_error(ArgumentError, /host/)
      expect { described_class.new(host: "https://example.com") }.to raise_error(ArgumentError, /host/)
      expect { described_class.new(host: "example.com", path: "cli") }.to raise_error(ArgumentError, /path/)
      expect { described_class.new(host: "example.com", scheme: "http") }.to raise_error(ArgumentError, /scheme/)
      expect { described_class.new(host: "example.com", scheme: "qrl") }.to raise_error(ArgumentError, /loopback/)
      expect(described_class.new(host: "localhost:8080", scheme: "qrl").origin).to eq("http://localhost:8080")
      expect { described_class.new(host: "example.com", path_extension: 0) }.to raise_error(ArgumentError, /path_extension/)
      expect { described_class.new(host: "example.com", nut_ttl: 0) }.to raise_error(ArgumentError, /nut_ttl/)
      expect { described_class.new(host: "example.com", cps_token_ttl: -1) }.to raise_error(ArgumentError, /cps_token_ttl/)
      expect { described_class.new(host: "example.com", on_unknown_identity: :maybe) }.to raise_error(ArgumentError, /on_unknown_identity/)
      expect { described_class.new(host: "example.com", ask: "text") }.to raise_error(ArgumentError, /ask/)
      expect { described_class.new(host: "example.com", sin: 5) }.to raise_error(ArgumentError, /sin/)
      expect { described_class.new(host: "example.com", on_authenticated: 5) }.to raise_error(ArgumentError, /on_authenticated/)
      expect { described_class.new(host: "example.com", cps_url: "x") }.to raise_error(ArgumentError, /cps_url/)
      expect { described_class.new(host: "example.com", clock: 1) }.to raise_error(ArgumentError, /clock/)
    end

    it "resolves ask and sin from statics or callables" do
      ask = SQRL::Ask.new(message: "?")
      c = described_class.new(host: "example.com", ask: ask, sin: "7")
      expect(c.ask_for({})).to be(ask)
      expect(c.sin_for({})).to eq("7")
      c = described_class.new(host: "example.com", ask: ->(ctx) { ctx[:a] }, sin: ->(_) { nil })
      expect(c.ask_for({ a: ask })).to be(ask)
      expect(c.sin_for({})).to be_nil
    end

    it "uses a custom cps_url builder" do
      c = described_class.new(host: "example.com", cps_url: ->(t, login) { "https://example.com/x?t=#{t}&l=#{login}" })
      expect(c.cps_url_for("tok", "L")).to eq("https://example.com/x?t=tok&l=L")
    end
  end

  describe SQRL::Server::Handler do
    let(:clock) { Struct.new(:now) { def call = now }.new(Time.at(1_700_000_000)) }
    let(:handler) { new_handler(clock: clock) }
    let(:id) { identity(31) }

    def login!(handler, identity, cps: true)
      login = handler.new_login_url(ip: FlowHelpers::IP)
      s = SQRL::Session.new(identity, login.url, options: SQRL::ClientOptions.new(cps: cps))
      exchange(handler, s, s.query)
      [login, s, exchange(handler, s, s.ident)]
    end

    it "rejects a non-Config" do
      expect { described_class.new(config: {}) }.to raise_error(ArgumentError)
    end

    it "issues login URLs with a cancel URL and optional path extension" do
      login = handler.new_login_url(ip: "1.1.1.1", cancel_url: "https://example.com/bye", return_to: "/after")
      expect(login.url).to match(%r{\Asqrl://example.com/cli.sqrl\?nut=[A-Za-z0-9_-]{16}&can=[A-Za-z0-9_-]+\z})
      expect(SQRL::URL.parse(login.url).cancel_url).to eq("https://example.com/bye")
      expect(login.b64).to eq(b64(login.url))
      expect(login.to_s).to eq(login.url)
      pending = handler.stores.pending_logins.find(login.pending_login_id)
      expect(pending.return_to).to eq("/after")
      expect(pending.ip).to eq("1.1.1.1")
      expect(pending.expires_at).to eq(clock.now + 300)
      expect(handler.new_login_url("my-id", ip: "1.1.1.1").pending_login_id).to eq("my-id")
    end

    it "reports status for unknown, pending and authenticated logins" do
      expect(handler.status("nope")).to eq(authenticated: false, idk: nil)
      expect(handler.status(nil)).to eq(authenticated: false, idk: nil)
      login, s, = login!(handler, id)
      expect(handler.status(login.pending_login_id)).to eq(authenticated: true, idk: s.idk_b64)
      clock.now += 301
      expect(handler.status(login.pending_login_id)).to eq(authenticated: false, idk: nil)
    end

    it "mints a one-time CPS token that expires" do
      _, s, result = login!(handler, id)
      token = result.cps_url[/t=(.+)\z/, 1]
      expect(s.cps_url).to eq(result.cps_url)
      expect(handler.claim_cps("")).to be_nil
      expect(handler.claim_cps(nil)).to be_nil
      expect(handler.claim_cps("#{token}x")).to be_nil
      claimed = handler.claim_cps(token)
      expect(claimed.authenticated_idk).to eq(s.idk)
      expect(claimed.cps_token).to be_nil
      expect(handler.claim_cps(token)).to be_nil

      _, _, result = login!(handler, id)
      token = result.cps_url[/t=(.+)\z/, 1]
      clock.now += 61
      expect(handler.claim_cps(token)).to be_nil
    end

    it "does not issue a CPS url without the cps option" do
      _, s, result = login!(handler, id, cps: false)
      expect(result.cps_url).to be_nil
      expect(s.cps_url).to be_nil
      expect(s.last_response.url).to be_nil
    end

    it "issues a CPS url on remove and clears the authentication" do
      login, s, = login!(handler, id)
      login2 = handler.new_login_url(ip: FlowHelpers::IP)
      s = SQRL::Session.new(id, login2.url, options: SQRL::ClientOptions.new(cps: true))
      exchange(handler, s, s.query)
      exchange(handler, s, s.ident)
      expect(handler.status(login2.pending_login_id)[:authenticated]).to be(true)
      # the suk only comes back in query replies, so a remove always follows a query
      exchange(handler, s, s.query)
      r = exchange(handler, s, s.remove(31.chr * 32))
      expect(r.tif).not_to be_error
      expect(r.cps_url).not_to be_nil
      expect(handler.status(login2.pending_login_id)).to eq(authenticated: false, idk: nil)
      expect(handler.claim_cps(r.cps_url[/t=(.+)\z/, 1])).not_to be_authenticated
      expect(handler.status(login.pending_login_id)[:authenticated]).to be(true)
    end

    it "expires nuts" do
      login = handler.new_login_url(ip: FlowHelpers::IP)
      s = SQRL::Session.new(id, login.url)
      q = s.query
      clock.now += 301
      r = handler.handle(nut: nut_of(q), body: q.body, ip: FlowHelpers::IP)
      expect(r.tif).to be_transient_error
    end

    it "prunes expired state" do
      handler.new_login_url(ip: FlowHelpers::IP)
      expect(handler.stores.nuts.size).to eq(1)
      expect(handler.stores.pending_logins.size).to eq(1)
      clock.now += 301
      handler.prune!
      expect(handler.stores.nuts.size).to eq(0)
      expect(handler.stores.pending_logins.size).to eq(0)
    end

    it "calls on_authenticated" do
      calls = []
      handler = new_handler(on_authenticated: ->(identity, login, cmd) { calls << [identity.idk, login.id, cmd] })
      login, s, = login!(handler, id)
      expect(calls).to eq([[s.idk, login.pending_login_id, :ident]])
    end

    it "refuses account creation under :refuse" do
      handler = new_handler(on_unknown_identity: :refuse)
      _, s, r = login!(handler, id)
      expect(r.tif).to be_command_failed
      expect(r).not_to be_authenticated
      expect(handler.stores.identities.count).to eq(0)
      expect(s.state).to be_failed
    end

    it "links new identities to the pending login's user under :link" do
      handler = new_handler(on_unknown_identity: :link)
      # without a signed-in user: refused
      _, _, r = login!(handler, id)
      expect(r.tif).to be_command_failed
      # with one: created and linked
      login = handler.new_login_url(ip: FlowHelpers::IP, link_user_ref: 42)
      s = SQRL::Session.new(id, login.url)
      exchange(handler, s, s.query)
      r = exchange(handler, s, s.ident)
      expect(r).to be_created
      expect(r.identity.user_ref).to eq(42)
      # an existing identity without a user picks up the link on login
      handler.stores.identities.update(s.idk, user_ref: nil)
      login = handler.new_login_url(ip: FlowHelpers::IP, link_user_ref: 43)
      s = SQRL::Session.new(id, login.url)
      exchange(handler, s, s.query)
      r = exchange(handler, s, s.ident)
      expect(r.identity.user_ref).to eq(43)
    end

    it "also links under :create when a user is present" do
      login = handler.new_login_url(ip: FlowHelpers::IP, link_user_ref: "u1")
      s = SQRL::Session.new(id, login.url)
      exchange(handler, s, s.query)
      r = exchange(handler, s, s.ident)
      expect(r.identity.user_ref).to eq("u1")
    end

    it "tolerates percent-encoded bodies" do
      login = handler.new_login_url(ip: FlowHelpers::IP)
      s = SQRL::Session.new(id, login.url)
      q = s.query
      encoded = q.body.gsub("-", "%2D").gsub("_", "%5F")
      r = handler.handle(nut: nut_of(q), body: encoded, ip: FlowHelpers::IP)
      expect(r.tif).not_to be_error
    end

    it "logs without leaking secrets" do
      lines = []
      logger = Struct.new(:lines) { def debug(msg) = lines << msg }.new(lines)
      handler = new_handler(logger: logger)
      _, s, = login!(handler, id)
      expect(lines.length).to eq(2)
      expect(lines.join).to include("ident", "authenticated=true")
      expect(lines.join).not_to include(s.idk_b64)
    end

    it "answers a transient error with a usable anonymous pending login" do
      r = handler.handle(nut: "unknown", body: "", ip: FlowHelpers::IP)
      expect(r.tif).to be_transient_error
      expect(r.pending_login_id).not_to be_nil
      expect(handler.stores.pending_logins.find(r.pending_login_id)).not_to be_nil
      expect(r.command).to be_nil
      expect(r.inspect).to include("tif=0x60")
    end

    it "serves the sin challenge in every response" do
      handler = new_handler(sin: "9")
      r = handler.handle(nut: "unknown", body: "", ip: FlowHelpers::IP)
      expect(SQRL::Util.b64u_decode(r.body)).to include("sin=9\r\n")
    end

    describe ".parse_form" do
      it "splits the body" do
        expect(described_class.parse_form("a=1&b=x%2Fy&c&\n")).to eq([%w[a 1], %w[b x/y], ["c", ""]])
      end
    end
  end

  describe SQRL::Server::Memory do
    let(:stores) { described_class.stores }

    it "consumes nuts exactly once, even concurrently" do
      stores.nuts.issue(nut: "n", pending_login_id: "p", expected_server: "s", ip: "ip", bound_idk: nil, expires_at: nil)
      results = Array.new(8) { Thread.new { stores.nuts.consume("n") } }.map(&:value)
      expect(results.compact.length).to eq(1)
      expect(results.compact.first.pending_login_id).to eq("p")
    end

    it "claims CPS tokens exactly once, even concurrently" do
      stores.pending_logins.create("p", ip: "ip", return_to: nil, expires_at: nil)
      stores.pending_logins.update("p", cps_token: "tok", cps_token_expires_at: nil)
      results = Array.new(8) { Thread.new { stores.pending_logins.claim_cps_token("tok") } }.map(&:value)
      expect(results.compact.length).to eq(1)
    end

    it "returns copies, not internal records" do
      created = stores.identities.create(idk: "a" * 32, suk: "s" * 32, vuk: "v" * 32)
      created.disabled = true
      expect(stores.identities.find("a" * 32)).not_to be_disabled
      expect { stores.identities.create(idk: "a" * 32, suk: "s" * 32, vuk: "v" * 32) }.to raise_error(ArgumentError)
      expect(stores.identities.update("zz" * 16, disabled: true)).to be_nil
      expect(stores.identities.rekey("zz" * 16, "y" * 32, suk: "s" * 32, vuk: "v" * 32, ins: nil)).to be_nil
      expect(stores.identities.all.length).to eq(1)
      expect(stores.pending_logins.update("missing", btn: 1)).to be_nil
      expect(stores.pending_logins.claim_cps_token(nil)).to be_nil
    end
  end

  describe SQRL::Server::Identity do
    it "has predicates and a safe inspect" do
      i = described_class.new(idk: "\x01" * 32, suk: "s", vuk: "v")
      expect(i).not_to be_disabled
      expect(i.logins).to eq(0)
      expect(i.inspect).to include(i.idk_b64)
    end
  end
end
