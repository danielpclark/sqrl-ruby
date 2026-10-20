# frozen_string_literal: true

require "logger"
require "stringio"

require "securerandom"

RSpec.describe SQRL::Rack::Middleware do
  let(:stores) { SQRL::Server::Memory.stores }
  let(:logins) { [] }
  let(:middleware_options) { { stores: stores, host: "example.com", after_login: "/home" } }
  let(:app) do
    opts = middleware_options
    inner = lambda do |env|
      sqrl = env["sqrl.server"]
      case env["PATH_INFO"]
      when "/login"
        [200, { "content-type" => "text/html" },
         [sqrl.login_block(cancel_url: "/bye", return_to: env["QUERY_STRING"][/rt=(.+)/, 1])]]
      when "/who"
        [200, { "content-type" => "text/plain" }, [sqrl.authenticated? ? sqrl.idk_b64 : "anonymous"]]
      when "/logout"
        sqrl.logout!
        [200, {}, ["bye"]]
      else
        [404, {}, ["nope"]]
      end
    end
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: SecureRandom.hex(64), key: "s"
      use SQRL::Rack::Middleware, opts
      run inner
    end.to_app
  end

  def visit_login(browser, extra = "")
    browser.get("/login#{extra}", {}, { "REMOTE_ADDR" => ClientHelpers::BROWSER_IP, "HTTPS" => "on" })
    expect(browser.last_response.status).to eq(200)
    login_url_from(browser.last_response.body)
  end

  it "serves the login page with a sqrl:// URL bound to the browser session" do
    browser = new_browser
    url = visit_login(browser)
    expect(url).to start_with("sqrl://example.com/sqrl/cli?nut=")
    expect(url).to include("&can=")
    expect(browser.last_response.body).to include('data-sqrl-status="/sqrl/status"', 'src="/sqrl/sqrl.js"')
    expect(stores.pending_logins.size).to eq(1)
  end

  it "serves sqrl.js with an ETag" do
    browser = new_browser
    browser.get("/sqrl/sqrl.js")
    expect(browser.last_response.status).to eq(200)
    expect(browser.last_response.headers["content-type"]).to include("javascript")
    etag = browser.last_response.headers["etag"]
    browser.get("/sqrl/sqrl.js", {}, { "HTTP_IF_NONE_MATCH" => etag })
    expect(browser.last_response.status).to eq(304)
  end

  describe "CPS login" do
    it "creates the account, then completes the login once in the right browser" do
      browser = new_browser
      url = visit_login(browser)
      client = new_client
      session = sqrl_login(client, url)
      expect(session.state).to eq(:known)
      cps = session.cps_url
      expect(cps).to start_with("https://example.com/sqrl/callback?t=")
      expect(client.last_response.headers["x-sqrl-tif"]).to eq("5")

      # a different browser cannot use the token (and burns it)
      other = new_browser
      other.get("/sqrl/callback?t=stolen")
      expect(other.last_response.status).to eq(403)

      path = cps.sub("https://example.com", "")
      browser.get(path)
      expect(browser.last_response.status).to eq(303)
      expect(browser.last_response.headers["location"]).to eq("/home")
      browser.get("/who")
      expect(browser.last_response.body).to eq(session.idk_b64)

      # token reuse fails
      browser.get(path)
      expect(browser.last_response.status).to eq(403)
      browser.get("/who")
      expect(browser.last_response.body).to eq(session.idk_b64) # still logged in
    end

    it "refuses a token claimed by a browser that did not start the login" do
      browser = new_browser
      url = visit_login(browser)
      session = sqrl_login(new_client, url)
      stranger = new_browser
      visit_login(stranger) # has its own pending login
      stranger.get(session.cps_url.sub("https://example.com", ""))
      expect(stranger.last_response.status).to eq(403)
      stranger.get("/who")
      expect(stranger.last_response.body).to eq("anonymous")
      # and the token is gone for the legitimate browser too (single use)
      browser.get(session.cps_url.sub("https://example.com", ""))
      expect(browser.last_response.status).to eq(403)
    end

    it "prefers a same-site return_to over after_login" do
      browser = new_browser
      url = visit_login(browser, "?rt=/account")
      session = sqrl_login(new_client, url)
      browser.get(session.cps_url.sub("https://example.com", ""))
      expect(browser.last_response.headers["location"]).to eq("/account")
    end

    it "ignores an off-site return_to" do
      browser = new_browser
      url = visit_login(browser, "?rt=//evil.example/x")
      session = sqrl_login(new_client, url)
      browser.get(session.cps_url.sub("https://example.com", ""))
      expect(browser.last_response.headers["location"]).to eq("/home")
    end

    it "ignores return_to values that browsers would turn into another host" do
      ["/\\evil.example/x", "/\t/evil.example", "/%5Cevil.example/x", "/ /evil.example"].each do |bad|
        browser = new_browser
        url = visit_login(browser, "?rt=#{Rack::Utils.escape(bad)}")
        session = sqrl_login(new_client, url)
        browser.get(session.cps_url.sub("https://example.com", ""))
        location = browser.last_response.headers["location"]
        expect(location).to eq("/home").or(satisfy { |l| l.start_with?("/") && !l.match?(/[\\\s]/) }),
                            "return_to #{bad.inspect} produced #{location.inspect}"
      end
    end
  end

  describe "non-CPS login from a client whose IP did not match" do
    def ident_from_elsewhere
      browser = new_browser
      url = visit_login(browser)
      session = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: false, noiptest: true))
      client = new_client
      post_sqrl(client, session, session.query, ip: "203.0.113.99")
      post_sqrl(client, session, session.ident, ip: "203.0.113.99")
      expect(session.state).to eq(:known)
      browser
    end

    it "is completable through the poll by default (a phone on another network is normal)" do
      browser = ident_from_elsewhere
      browser.get("/sqrl/status")
      expect(JSON.parse(browser.last_response.body)["authenticated"]).to be(true)
      browser.get("/sqrl/callback")
      expect(browser.last_response.status).to eq(303)
    end

    context "when the site opts into poll_requires_ip_match" do
      let(:middleware_options) { super().merge(poll_requires_ip_match: true) }

      it "is refused through the poll" do
        browser = ident_from_elsewhere
        browser.get("/sqrl/status")
        expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => false)
        browser.get("/sqrl/callback")
        expect(browser.last_response.status).to eq(403)
      end
    end
  end

  describe "non-CPS login (polling)" do
    it "reports authenticated on the status poll, then completes once via the callback" do
      browser = new_browser
      url = visit_login(browser)
      browser.get("/sqrl/status")
      expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => false)

      session = sqrl_login(new_client, url, cps: false)
      expect(session.cps_url).to be_nil
      browser.get("/sqrl/status")
      expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => true, "next" => "/sqrl/callback")

      stranger = new_browser
      stranger.get("/sqrl/callback")
      expect(stranger.last_response.status).to eq(403)

      browser.get("/sqrl/callback")
      expect(browser.last_response.status).to eq(303)
      browser.get("/who")
      expect(browser.last_response.body).to eq(session.idk_b64)
      browser.get("/sqrl/callback")
      expect(browser.last_response.status).to eq(403)
      browser.get("/sqrl/status")
      expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => false)
    end

    it "reports an expired pending login" do
      now = Time.now
      middleware_options[:clock] = -> { now }
      browser = new_browser
      visit_login(browser)
      now += 301
      browser.get("/sqrl/status")
      expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => false, "expired" => true)
    end
  end

  describe "protocol endpoint" do
    it "answers garbage with a protocol error body, status 200" do
      client = new_client
      client.post("/sqrl/cli?nut=bogus", "client=x&server=y&ids=z",
                  { "CONTENT_TYPE" => "application/x-www-form-urlencoded" })
      expect(client.last_response.status).to eq(200)
      tif = client.last_response.headers["x-sqrl-tif"].to_i(16)
      expect(tif & SQRL::Tif::TRANSIENT_ERROR).not_to eq(0)
      expect(client.last_response.body).to match(/\A[A-Za-z0-9_-]+\z/)
    end

    it "enforces the IP match" do
      browser = new_browser
      url = visit_login(browser)
      client = new_client
      session = SQRL::Session.new(identity, url)
      post_sqrl(client, session, session.query, ip: "203.0.113.99")
      expect(session.ip_check_failed?).to be(true)
    end

    it "never reaches the application" do
      client = new_client
      client.post("/sqrl/cli?nut=x", "")
      expect(client.last_response.body).not_to eq("nope")
    end
  end

  describe "options" do
    it "runs on_login and after_login callables, and does not keep the identity in the session when asked" do
      middleware_options[:on_login] = ->(env, identity, pl) { logins << [env["PATH_INFO"], identity.idk_b64, pl.id] }
      middleware_options[:after_login] = ->(_env, completion) { "/u/#{completion.idk_b64}" }
      browser = new_browser
      url = visit_login(browser)
      session = sqrl_login(new_client, url)
      browser.get(session.cps_url.sub("https://example.com", ""))
      expect(browser.last_response.headers["location"]).to eq("/u/#{session.idk_b64}")
      expect(logins).to eq([["/sqrl/callback", session.idk_b64, stores.pending_logins.find(logins.first[2]).id]])
      browser.get("/who")
      expect(browser.last_response.body).to eq("anonymous")
    end

    it "redirects to failure_path when set" do
      middleware_options[:failure_path] = "/login?failed=1"
      browser = new_browser
      browser.get("/sqrl/callback?t=nope")
      expect(browser.last_response.status).to eq(303)
      expect(browser.last_response.headers["location"]).to eq("/login?failed=1")
    end

    it "refuses unknown identities with on_unknown_identity: :refuse" do
      middleware_options[:on_unknown_identity] = :refuse
      browser = new_browser
      url = visit_login(browser)
      session = sqrl_login(new_client, url)
      expect(session.state).to eq(:failed)
      expect(stores.identities.count).to eq(0)
    end

    it "issues sqrl:// even for a plain-http loopback request (the scheme is never guessed)" do
      middleware_options.delete(:host)
      browser = Rack::Test::Session.new(Rack::MockSession.new(app, "localhost"))
      browser.get("/login", {}, { "REMOTE_ADDR" => "127.0.0.1" })
      expect(login_url_from(browser.last_response.body)).to start_with("sqrl://localhost/sqrl/cli?nut=")
    end

    it "issues qrl:// only in the explicit insecure_http testing mode, and only for loopback hosts" do
      SQRL::Server::Config.reset_warnings!
      opts = middleware_options.merge(host: "localhost", insecure_http: true, logger: Logger.new(log = StringIO.new))
      insecure = Rack::Builder.new do
        use Rack::Session::Cookie, secret: "x" * 64, same_site: :lax
        use SQRL::Rack::Middleware, opts
        run ->(env) { [200, { "content-type" => "text/html" }, [env["sqrl.server"].login_block]] }
      end.to_app
      browser = Rack::Test::Session.new(Rack::MockSession.new(insecure, "localhost"))
      browser.get("/", {}, { "REMOTE_ADDR" => "127.0.0.1" })
      expect(login_url_from(browser.last_response.body)).to start_with("qrl://localhost/sqrl/cli?nut=")
      expect(log.string).to include("insecure_http is a loopback-only testing mode")

      bad = Rack::Builder.new do
        use Rack::Session::Cookie, secret: "x" * 64, same_site: :lax
        use SQRL::Rack::Middleware, opts.merge(host: "example.com")
        run ->(env) { [200, { "content-type" => "text/html" }, [env["sqrl.server"].login_block]] }
      end.to_app
      browser = Rack::Test::Session.new(Rack::MockSession.new(bad, "example.com"))
      expect { browser.get("/") }.to raise_error(ArgumentError, /loopback/)
    end

    it "accepts options from a callable, resolved on first use" do
      calls = 0
      mw = described_class.new(->(_env) { [200, {}, ["x"]] }, lambda {
        calls += 1
        { host: "h.example" }
      })
      expect(calls).to eq(0)
      expect(mw.options[:host]).to eq("h.example")
      mw.options
      expect(calls).to eq(1)
    end

    it "honours a mount prefix in issued URLs and browser URLs" do
      opts = middleware_options
      inner = ->(env) { [200, {}, [env["sqrl.server"].login_block]] }
      mounted = Rack::Builder.new do
        use Rack::Session::Cookie, secret: SecureRandom.hex(64)
        map "/app" do
          use SQRL::Rack::Middleware, opts
          run inner
        end
      end.to_app
      browser = new_browser(mounted)
      browser.get("/app/login", {}, { "REMOTE_ADDR" => ClientHelpers::BROWSER_IP })
      body = browser.last_response.body
      expect(login_url_from(body)).to start_with("sqrl://example.com/app/sqrl/cli?nut=")
      expect(body).to include('data-sqrl-status="/app/sqrl/status"', 'src="/app/sqrl/sqrl.js"')
      session = sqrl_login(new_client(mounted), login_url_from(body))
      expect(session.cps_url).to start_with("https://example.com/app/sqrl/callback?t=")
    end
  end

  it "raises a clear error without a session middleware" do
    bare = Rack::Builder.new do
      use SQRL::Rack::Middleware, host: "example.com"
      run ->(env) { [200, {}, [env["sqrl.server"].login_url.url]] }
    end.to_app
    expect { new_browser(bare).get("/") }.to raise_error(SQRL::Rack::Error, /session/)
  end

  it "logs out" do
    browser = new_browser
    url = visit_login(browser)
    session = sqrl_login(new_client, url)
    browser.get(session.cps_url.sub("https://example.com", ""))
    browser.get("/logout")
    browser.get("/who")
    expect(browser.last_response.body).to eq("anonymous")
  end
end
