# frozen_string_literal: true

require "securerandom"

RSpec.describe OmniAuth::Strategies::SQRL do
  let(:stores) { SQRL::Server::Memory.stores }
  let(:provider_options) { { stores: stores, host: "example.com" } }
  let(:app) { build_app(provider_options) }

  def build_app(opts)
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: SecureRandom.hex(64), key: "s"
      use OmniAuth::Builder do
        provider :sqrl, **opts
      end
      run lambda { |env|
        req = Rack::Request.new(env)
        case req.path_info
        when %r{/callback\z}
          auth = env["omniauth.auth"]
          [200, { "content-type" => "application/json" }, [JSON.generate(auth ? auth.to_hash : { "none" => true })]]
        when "/auth/failure"
          [200, { "content-type" => "text/plain" }, ["failure:#{req.params['message']}"]]
        else
          [404, { "content-type" => "text/plain" }, ["app:#{req.path_info}"]]
        end
      }
    end.to_app
  end

  def auth_hash(browser)
    expect(browser.last_response.status).to eq(200)
    JSON.parse(browser.last_response.body)
  end

  def cps_login(browser, url, id = identity)
    session = sqrl_login(new_client, url, id)
    expect(session.state).to eq(:known)
    browser.get(session.cps_url.sub("https://example.com", ""))
    session
  end

  describe "request phase" do
    it "renders the login page with a sqrl:// URL bound to the browser session" do
      browser = new_browser
      url = start_login(browser)
      body = browser.last_response.body
      expect(url).to start_with("sqrl://example.com/auth/sqrl/cli?nut=")
      expect(body).to include('data-sqrl-status="/auth/sqrl/status"', 'src="/auth/sqrl/sqrl.js"', "<svg",
                              "<title>Sign in with SQRL</title>")
      expect(stores.pending_logins.size).to eq(1)
    end

    it "uses the origin as the cancel link and honours title and login_block options" do
      app = build_app(provider_options.merge(title: "Acme <SQRL>", login_block: { qr: false, link_text: "Go" }))
      browser = new_browser(app)
      start_login(browser, "/auth/sqrl", { "HTTP_REFERER" => "https://example.com/start" })
      body = browser.last_response.body
      expect(body).to include("Acme &lt;SQRL&gt;", ">Go</a>", 'href="https://example.com/start"')
      expect(body).not_to include("<svg")
    end

    it "serves sqrl.js and the status poll from the middleware" do
      browser = new_browser
      browser.get("/auth/sqrl/sqrl.js")
      expect(browser.last_response.status).to eq(200)
      expect(browser.last_response.headers["content-type"]).to include("javascript")
      browser.get("/auth/sqrl/status")
      expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => false)
    end

    it "lets unrelated requests through to the application" do
      browser = new_browser
      browser.get("/elsewhere")
      expect(browser.last_response.body).to eq("app:/elsewhere")
    end
  end

  describe "CPS login" do
    it "creates the account and yields an auth hash with uid and SQRL facts" do
      browser = new_browser
      url = start_login(browser)
      session = cps_login(browser, url)
      auth = auth_hash(browser)
      expect(auth["provider"]).to eq("sqrl")
      expect(auth["uid"]).to eq(session.idk_b64)
      expect(auth["info"].compact).to eq({})
      sqrl = auth["extra"]["sqrl"]
      expect(sqrl).to include("idk" => session.idk_b64, "created" => true, "rekeyed_from" => nil,
                              "disabled" => false, "via" => "cps", "logins" => 1)
      expect(sqrl["options"]).to eq("sqrlonly" => false, "hardlock" => false)
      expect(SQRL::Util.b64u_decode(sqrl["suk"]).bytesize).to eq(32)
      expect(SQRL::Util.b64u_decode(sqrl["vuk"]).bytesize).to eq(32)
      expect(browser.last_request.env["rack.session"]).not_to have_key("omniauth.sqrl.identity")
    end

    it "reports a second login as not created, and fills info through the info option" do
      app = build_app(provider_options.merge(info: ->(identity) { { "name" => "sqrl:#{identity.idk_b64[0, 6]}" } }))
      browser = new_browser(app)
      cps_login(browser, start_login(browser))
      browser = new_browser(app)
      session = cps_login(browser, start_login(browser))
      auth = auth_hash(browser)
      expect(auth["extra"]["sqrl"]).to include("created" => false, "logins" => 2)
      expect(auth["info"]["name"]).to eq("sqrl:#{session.idk_b64[0, 6]}")
    end

    it "reports a re-key with the previous identity key" do
      browser = new_browser
      old = identity(7)
      cps_login(browser, start_login(browser), old)
      newer = SQRL::UnlockedIdentity.from_iuk(8.chr * 32, [7.chr * 32])
      browser = new_browser
      session = cps_login(browser, start_login(browser), newer)
      auth = auth_hash(browser)
      expect(auth["uid"]).to eq(session.idk_b64)
      expect(auth["extra"]["sqrl"]["rekeyed_from"]).to eq(SQRL::Util.b64u_encode(old.site_public_key("example.com")))
    end

    it "refuses a reused token and a token in another browser" do
      browser = new_browser
      url = start_login(browser)
      session = sqrl_login(new_client, url)
      path = session.cps_url.sub("https://example.com", "")

      other = new_browser
      other.get(path)
      expect(other.last_response.status).to eq(302)
      expect(other.last_response.headers["location"]).to include("/auth/failure?message=invalid_credentials")

      browser.get(path)
      expect(browser.last_response.status).to eq(302) # the token was burnt by the other browser
      expect(browser.last_response.headers["location"]).to include("invalid_credentials")
    end

    it "fails cleanly on a callback without any pending login" do
      browser = new_browser
      browser.get("/auth/sqrl/callback")
      expect(browser.last_response.status).to eq(302)
      browser.get(request_uri(browser.last_response.headers["location"]))
      expect(browser.last_response.body).to eq("failure:invalid_credentials")
    end
  end

  describe "poll login (no CPS)" do
    it "completes through the cookie-bound pending login exactly once" do
      browser = new_browser
      url = start_login(browser)
      session = sqrl_login(new_client, url, cps: false)
      expect(session.cps_url).to be_nil

      browser.get("/auth/sqrl/status")
      expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => true, "next" => "/auth/sqrl/callback")

      browser.get("/auth/sqrl/callback")
      auth = auth_hash(browser)
      expect(auth["uid"]).to eq(session.idk_b64)
      expect(auth["extra"]["sqrl"]["via"]).to eq("poll")

      browser.get("/auth/sqrl/callback")
      expect(browser.last_response.status).to eq(302)
      expect(browser.last_response.headers["location"]).to include("invalid_credentials")
    end
  end

  describe "failures and policies" do
    it "fails with sqrl_disabled when the authenticated identity was disabled" do
      browser = new_browser
      url = start_login(browser)
      session = sqrl_login(new_client, url, cps: false)
      stores.identities.update(session.idk, disabled: true)
      browser.get("/auth/sqrl/callback")
      expect(browser.last_response.status).to eq(302)
      expect(browser.last_response.headers["location"]).to include("message=sqrl_disabled")
    end

    it "refuses unknown identities under :refuse" do
      app = build_app(provider_options.merge(on_unknown_identity: :refuse))
      browser = new_browser(app)
      url = start_login(browser)
      session = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: true))
      client = new_client(app)
      post_sqrl(client, session, session.query)
      post_sqrl(client, session, session.ident)
      expect(session.state).to eq(:failed)
      expect(stores.identities.count).to eq(0)
    end

    it "links new identities to the user named by link_user_ref under :link" do
      app = build_app(provider_options.merge(on_unknown_identity: :link,
                                             link_user_ref: ->(env) { env["rack.session"]["user_id"] }))
      browser = new_browser(app)
      # nobody signed in: creation refused
      url = start_login(browser)
      session = sqrl_login(new_client(app), url)
      expect(session.state).to eq(:failed)

      browser.get("/auth/failure") # any request to put user_id in the session via the app? use the session directly
      browser.last_request.env["rack.session"]["user_id"] = 42
      browser.post("/auth/sqrl", {}, { "REMOTE_ADDR" => ClientHelpers::BROWSER_IP, "HTTPS" => "on",
                                        "rack.session" => browser.last_request.env["rack.session"] })
      url = login_url_from(browser.last_response.body)
      session = cps_login(browser, url)
      auth = auth_hash(browser)
      expect(auth["uid"]).to eq(session.idk_b64)
      expect(auth["extra"]["sqrl"]["user_ref"]).to eq(42)
    end

    it "requires the client IP to match unless configured otherwise" do
      browser = new_browser
      url = start_login(browser)
      session = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: true))
      post_sqrl(new_client, session, session.query, ip: "203.0.113.9")
      expect(session.ip_check_failed?).to be(true)

      app = build_app(provider_options.merge(require_ip_match: false))
      browser = new_browser(app)
      url = start_login(browser)
      session = sqrl_login(new_client(app), url, ip: "203.0.113.9")
      expect(session.state).to eq(:known)
    end
  end

  describe "configuration" do
    it "serves everything under a custom path prefix" do
      app = build_app(provider_options.merge(path_prefix: "/login"))
      browser = new_browser(app)
      url = start_login(browser, "/login/sqrl")
      expect(url).to start_with("sqrl://example.com/login/sqrl/cli?nut=")
      expect(browser.last_response.body).to include('data-sqrl-status="/login/sqrl/status"')
      session = sqrl_login(new_client(app), url)
      expect(session.cps_url).to start_with("https://example.com/login/sqrl/callback?t=")
      browser.get(session.cps_url.sub("https://example.com", ""))
      expect(auth_hash(browser)["uid"]).to eq(session.idk_b64)
    end

    it "issues qrl:// URLs for plain-http loopback hosts and sqrl:// otherwise" do
      app = build_app(stores: stores)
      browser = Rack::Test::Session.new(Rack::MockSession.new(app, "localhost"))
      browser.post("/auth/sqrl", {}, { "REMOTE_ADDR" => "127.0.0.1" })
      expect(login_url_from(browser.last_response.body)).to start_with("qrl://localhost/auth/sqrl/cli?nut=")

      browser = Rack::Test::Session.new(Rack::MockSession.new(app, "site.test"))
      browser.post("/auth/sqrl", {}, { "REMOTE_ADDR" => "127.0.0.1" })
      expect(login_url_from(browser.last_response.body)).to start_with("sqrl://site.test/auth/sqrl/cli?nut=")
    end

    context "without a stores: option" do
      let(:provider_options) { { host: "example.com" } }

      it "defaults to process-wide in-memory stores" do
        browser = new_browser
        session = cps_login(browser, start_login(browser))
        expect(auth_hash(browser)["uid"]).to eq(session.idk_b64)
        browser = new_browser
        cps_login(browser, start_login(browser))
        expect(auth_hash(browser)["extra"]["sqrl"]["created"]).to be(false)
        expect(described_class.default_stores.identities.find(session.idk)).not_to be_nil
      end
    end

    it "supports OmniAuth test mode" do
      OmniAuth.config.test_mode = true
      OmniAuth.config.mock_auth[:sqrl] = OmniAuth::AuthHash.new(provider: "sqrl", uid: "mock-idk",
                                                                extra: { sqrl: { created: true } })
      browser = new_browser
      browser.post("/auth/sqrl")
      expect(browser.last_response.status).to eq(302)
      browser.get("/auth/sqrl/callback")
      expect(auth_hash(browser)).to include("uid" => "mock-idk")
    end
  end
end
