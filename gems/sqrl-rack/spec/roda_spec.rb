# frozen_string_literal: true

require "rack/session"
require "json"

begin
  require "roda"
  require "roda/plugins/sqrl"
rescue LoadError
  RSpec.describe "Roda plugin" do
    it("needs the roda gem") { skip "roda is not installed" }
  end
  return
end

RSpec.describe Roda::RodaPlugins::SQRL do
  let(:stores) { SQRL::Server::Memory.stores }
  let(:seen) { [] }

  let(:app) do
    stores_ = stores
    seen_ = seen
    Class.new(Roda) do
      use Rack::Session::Cookie, secret: "x" * 64, same_site: :lax
      plugin :sqrl, stores: stores_, host: "example.com", after_login: "/home"
      sqrl_on_login { |identity, env| seen_ << [identity.idk_b64, env["PATH_INFO"]] }

      route do |r|
        r.get("login") { sqrl_login_block(cancel_url: "/") }
        r.get("home") { "home" }
        r.get("who") { sqrl_authenticated? ? current_sqrl_identity.idk_b64 : "anonymous" }
        r.get("rwho") { r.sqrl_authenticated? ? r.current_sqrl_identity.idk_b64 : "anonymous" }
        r.post("logout") do
          sqrl_logout!
          "bye"
        end
      end
    end
  end

  def visit_login(browser)
    browser.get("/login", {}, { "REMOTE_ADDR" => ClientHelpers::BROWSER_IP, "HTTPS" => "on" })
    expect(browser.last_response.status).to eq(200)
    login_url_from(browser.last_response.body)
  end

  it "renders the login block and completes a CPS login through the middleware" do
    browser = new_browser
    url = visit_login(browser)
    expect(url).to start_with("sqrl://example.com/sqrl/cli?nut=")
    expect(browser.last_response.body).to include('data-sqrl-status="/sqrl/status"', "<svg")

    session = sqrl_login(new_client, url)
    browser.get(session.cps_url.sub("https://example.com", ""))
    expect(browser.last_response.status).to eq(303)
    expect(browser.last_response.headers["location"]).to eq("/home")
    expect(seen).to eq([[session.idk_b64, "/sqrl/callback"]])

    browser.get("/who")
    expect(browser.last_response.body).to eq(session.idk_b64)
    browser.get("/rwho")
    expect(browser.last_response.body).to eq(session.idk_b64)

    browser.post("/logout")
    browser.get("/who")
    expect(browser.last_response.body).to eq("anonymous")
  end

  it "serves the status poll and the script from the middleware" do
    browser = new_browser
    visit_login(browser)
    browser.get("/sqrl/status")
    expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => false)
    browser.get("/sqrl/sqrl.js")
    expect(browser.last_response.headers["content-type"]).to include("javascript")
  end

  it "exposes the options it was configured with and installs the middleware once" do
    expect(app.sqrl_options).to include(host: "example.com")
    expect(app.opts[:sqrl_middleware_installed]).to be(true)
    subclass = Class.new(app) { plugin :sqrl, after_login: "/elsewhere" }
    expect(subclass.sqrl_options).to include(host: "example.com", after_login: "/elsewhere")
  end

  it "raises a clear error when no Rack session middleware precedes it" do
    stores_ = stores
    sessionless = Class.new(Roda) do
      plugin :sqrl, stores: stores_, host: "example.com"
      route { |r| r.get("login") { sqrl_login_block } }
    end
    browser = new_browser(sessionless)
    expect { browser.get("/login") }.to raise_error(SQRL::Rack::Error, /session/i)
  end
end
