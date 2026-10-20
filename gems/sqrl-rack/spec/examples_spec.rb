# frozen_string_literal: true

# Boots each example application from its config.ru and drives a full login.
RSpec.describe "example applications" do
  APPS = {} # rubocop:disable Style/MutableConstant -- a per-run cache of loaded example apps

  def load_example(name)
    APPS[name] ||= begin
      app = Rack::Builder.parse_file(File.expand_path("../../../examples/#{name}/config.ru", __dir__))
      app.is_a?(Array) ? app.first : app
    end
  end

  shared_examples "a SQRL example app" do |name|
    let(:app) { load_example(name) }

    it "#{name}: home, login page, protected page, CPS login, logout" do
      browser = new_browser
      browser.get("/")
      expect(browser.last_response.status).to eq(200)
      expect(browser.last_response.body).to include("Not logged in")

      browser.get("/protected")
      expect(browser.last_response.status).to eq(403)

      browser.get("/login", {}, { "REMOTE_ADDR" => ClientHelpers::BROWSER_IP, "HTTPS" => "on" })
      expect(browser.last_response.status).to eq(200)
      url = login_url_from(browser.last_response.body)
      expect(url).to start_with("sqrl://example.com/sqrl/cli?nut=")
      expect(browser.last_response.body).to include("<svg", "sqrl.js")

      session = sqrl_login(new_client, url)
      expect(session.state).to eq(:known)
      browser.get(session.cps_url.sub("https://example.com", ""))
      expect(browser.last_response.status).to eq(303)
      expect(browser.last_response.headers["location"]).to eq("/protected")

      browser.get("/protected")
      expect(browser.last_response.status).to eq(200)
      expect(browser.last_response.body).to include(session.idk_b64)
      browser.get("/")
      expect(browser.last_response.body).to include("Logged in as")

      browser.post("/logout")
      expect(browser.last_response.status).to eq(303)
      browser.get("/protected")
      expect(browser.last_response.status).to eq(403)
    end

    it "#{name}: completes a non-CPS login through the poll and callback" do
      browser = new_browser
      browser.get("/login", {}, { "REMOTE_ADDR" => ClientHelpers::BROWSER_IP, "HTTPS" => "on" })
      url = login_url_from(browser.last_response.body)
      sqrl_login(new_client, url, cps: false)
      browser.get("/sqrl/status")
      expect(JSON.parse(browser.last_response.body)).to include("authenticated" => true)
      browser.get("/sqrl/callback")
      expect(browser.last_response.status).to eq(303)
      browser.get("/protected")
      expect(browser.last_response.status).to eq(200)
    end
  end

  it_behaves_like "a SQRL example app", "rack-app"
  it_behaves_like "a SQRL example app", "sinatra-app"
end
