# frozen_string_literal: true

require "securerandom"
require "logger"
require "stringio"

RSpec.describe SQRL::Rack::HostResolver do
  def request_for(host, scheme: "https")
    Rack::Request.new(Rack::MockRequest.env_for("#{scheme}://#{host}/login"))
  end

  it "uses the configured host without warning or limit" do
    log = StringIO.new
    resolver = described_class.new(host: "example.com", logger: Logger.new(log), limit: 1)
    expect(resolver.resolve(request_for("evil.example"))).to eq(["example.com", "sqrl"])
    20.times { |i| resolver.fetch(["example.com", "sqrl", "/p#{i}"]) { i } }
    expect(resolver.size).to eq(20)
    expect(log.string).to be_empty
  end

  it "derives the host from the request, warning once, and bounds the cache" do
    log = StringIO.new
    resolver = described_class.new(logger: Logger.new(log), limit: 2)
    expect(resolver.resolve(request_for("a.example"))).to eq(["a.example", "sqrl"])
    expect(resolver.resolve(request_for("localhost:3000", scheme: "http"))).to eq(["localhost:3000", "qrl"])
    expect(resolver.resolve(request_for("[::1]:3000", scheme: "http"))).to eq(["[::1]:3000", "qrl"])
    expect(resolver.resolve(request_for("[2001:db8::1]:3000", scheme: "http"))).to eq(["[2001:db8::1]:3000", "sqrl"])
    expect(log.string.scan("host not configured").size).to eq(1)

    resolver.fetch(["a.example", "sqrl", ""]) { 1 }
    resolver.fetch(["a.example", "sqrl", "/mounted"]) { 2 } # same host, different prefix: fine
    resolver.fetch(["b.example", "sqrl", ""]) { 3 }
    expect { resolver.fetch(["c.example", "sqrl", ""]) { 4 } }.to raise_error(SQRL::Rack::HostNotAllowed, /limit 2/)
    expect(resolver.fetch(["a.example", "sqrl", ""]) { 99 }).to eq(1)
  end

  it "rejects derived hosts outside allowed_hosts" do
    resolver = described_class.new(allowed_hosts: ["good.example", /\A[a-z]+\.tenants\.example\z/],
                                   logger: Logger.new(nil))
    expect(resolver.resolve(request_for("good.example:8443")).first).to eq("good.example:8443")
    expect(resolver.resolve(request_for("acme.tenants.example")).first).to eq("acme.tenants.example")
    expect { resolver.resolve(request_for("evil.example")) }.to raise_error(SQRL::Rack::HostNotAllowed, /allowed_hosts/)
  end
end

RSpec.describe SQRL::Rack::Middleware, "hardening" do
  let(:stores) { SQRL::Server::Memory.stores }
  let(:middleware_options) { { stores: stores, host: "example.com", after_login: "/home", logger: Logger.new(nil) } }
  let(:app) do
    opts = middleware_options
    inner = lambda do |env|
      sqrl = env["sqrl.server"]
      case env["PATH_INFO"]
      when "/login"
        [200, { "content-type" => "text/html" }, [sqrl.login_block(return_to: "/after")]]
      when "/who"
        [200, { "content-type" => "text/plain" }, [sqrl.authenticated? ? sqrl.idk_b64 : "anonymous"]]
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

  def browser_for(host)
    Rack::Test::Session.new(Rack::MockSession.new(app, host))
  end

  def visit_login(browser)
    browser.get("/login", {}, { "REMOTE_ADDR" => ClientHelpers::BROWSER_IP, "HTTPS" => "on" })
    login_url_from(browser.last_response.body)
  end

  describe "hosts" do
    it "answers 400 for a derived host outside allowed_hosts and beyond the cache limit" do
      middleware_options.delete(:host)
      middleware_options[:allowed_hosts] = [/\A[a-c]\.example\z/]
      middleware_options[:host_cache_limit] = 2
      expect(visit_login(browser_for("a.example"))).to start_with("sqrl://a.example/sqrl/cli?nut=")
      expect(visit_login(browser_for("b.example"))).to start_with("sqrl://b.example/sqrl/cli?nut=")

      browser = browser_for("z.example")
      browser.get("/login", {}, { "HTTPS" => "on" })
      expect(browser.last_response.status).to eq(400)
      expect(browser.last_response.body).to include("allowed_hosts")

      browser = browser_for("c.example")
      browser.get("/login", {}, { "HTTPS" => "on" })
      expect(browser.last_response.status).to eq(400)
      expect(browser.last_response.body).to include("limit 2")

      client = browser_for("c.example")
      client.post("/sqrl/cli?nut=x", "")
      expect(client.last_response.status).to eq(400)
    end
  end

  describe "rate limiting" do
    it "turns RateLimited from before_handle into 429 on the SQRL endpoint" do
      middleware_options[:before_handle] = lambda { |ctx|
        raise SQRL::Server::RateLimited.new("too many", retry_after: 15) if ctx[:phase] == :request
      }
      browser = new_browser
      url = visit_login(browser)
      client = new_client
      session = SQRL::Session.new(identity, url)
      req = session.query
      uri = URI.parse(req.url)
      client.post("#{uri.path}?#{uri.query}", req.body, { "CONTENT_TYPE" => "application/x-www-form-urlencoded" })
      expect(client.last_response.status).to eq(429)
      expect(client.last_response.headers["retry-after"]).to eq("15")
      expect(client.last_response.body).to include("too many")
      expect(stores.nuts.size).to eq(1), "the login nut was not consumed"
    end

    it "degrades the login block to a message when before_issue refuses" do
      middleware_options[:before_issue] = ->(_ctx) { raise SQRL::Server::RateLimited, "slow down" }
      browser = new_browser
      browser.get("/login", {}, { "HTTPS" => "on" })
      expect(browser.last_response.status).to eq(200)
      expect(browser.last_response.body).to include("data-sqrl-unavailable", "slow down")
      expect(browser.last_response.body).not_to include("data-sqrl-login")
      expect(stores.pending_logins.size).to eq(0)

      browser.get("/sqrl/refresh", {}, { "HTTPS" => "on" })
      expect(browser.last_response.status).to eq(429)
      expect(JSON.parse(browser.last_response.body)).to include("error" => "rate_limited")
    end
  end

  describe "refresh" do
    it "hands the page a fresh login URL bound to the same browser session, keeping return_to" do
      browser = new_browser
      first_url = visit_login(browser)
      expect(browser.last_response.body).to include('data-sqrl-refresh="/sqrl/refresh"', "data-sqrl-refresh-button",
                                                    "data-sqrl-qr", 'data-sqrl-text-message="')
      pending = stores.pending_logins.instance_variable_get(:@logins) # memory store internals, spec only
      first_id = pending.keys.first

      browser.get("/sqrl/refresh", {}, { "HTTPS" => "on", "REMOTE_ADDR" => ClientHelpers::BROWSER_IP })
      expect(browser.last_response.status).to eq(200)
      json = JSON.parse(browser.last_response.body)
      expect(json["sqrl_url"]).to start_with("sqrl://example.com/sqrl/cli?nut=")
      expect(json["sqrl_url"]).not_to eq(first_url)
      expect(json).to include("status_url" => "/sqrl/status", "refresh_url" => "/sqrl/refresh")
      expect(json["qr_svg"]).to include("<svg")

      expect(pending.size).to eq(2)
      new_login = pending.values.find { |l| l.id != first_id }
      expect(new_login.return_to).to eq("/after")

      # the new URL completes a login in this browser; the old one is detached from the session
      session = sqrl_login(new_client, json["sqrl_url"])
      browser.get(session.cps_url.sub("https://example.com", ""))
      expect(browser.last_response.status).to eq(303)
      expect(browser.last_response.headers["location"]).to eq("/after")

      browser.get("/sqrl/refresh?qr=0", {}, { "HTTPS" => "on" })
      expect(JSON.parse(browser.last_response.body)).not_to have_key("qr_svg")
    end
  end
end

RSpec.describe SQRL::Rack::LoginBlock, "hardening" do
  it "drops attribute names outside the HTML grammar and escapes their values" do
    html = described_class.render(login_url: "sqrl://e.com/?nut=1", status_url: "/s", qr: false,
                                  extra_attrs: { "data-ok" => "v", "onload=alert(1) x" => "y", "data-q\"" => "z" })
    expect(html).to include('data-ok="v"')
    expect(html).not_to include("onload", "alert", 'data-q"')
  end

  it "renders the unavailable message escaped" do
    html = described_class.unavailable(message: "<b>busy</b>")
    expect(html).to include("data-sqrl-unavailable", "&lt;b&gt;busy&lt;/b&gt;", "sqrl-login--unavailable")
    expect(html).not_to include("<b>")
  end
end
