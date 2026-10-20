# frozen_string_literal: true

# Boots examples/omniauth-app from its config.ru and drives a full login.
RSpec.describe "examples/omniauth-app" do
  let(:app) do
    app = Rack::Builder.parse_file(File.expand_path("../../../examples/omniauth-app/config.ru", __dir__))
    app.is_a?(Array) ? app.first : app
  end

  it "signs in with SQRL through the OmniAuth provider" do
    browser = new_browser
    browser.get("/")
    expect(browser.last_response.status).to eq(200)
    expect(browser.last_response.body).to include("Not logged in", 'action="/auth/sqrl"')
    token = browser.last_response.body[/name="authenticity_token" value="([^"]+)"/, 1]
    expect(token).not_to be_nil

    browser.get("/protected")
    expect(browser.last_response.status).to eq(403)

    browser.post("/auth/sqrl", { "authenticity_token" => token },
                 { "REMOTE_ADDR" => ClientHelpers::BROWSER_IP, "HTTPS" => "on", "HTTP_REFERER" => "https://example.com/" })
    expect(browser.last_response.status).to eq(200)
    url = login_url_from(browser.last_response.body)
    expect(url).to start_with("sqrl://example.com/auth/sqrl/cli?nut=")
    expect(browser.last_response.body).to include("<svg", "sqrl.js")

    session = sqrl_login(new_client, url)
    expect(session.state).to eq(:known)
    browser.get(session.cps_url.sub("https://example.com", ""))
    expect(browser.last_response.status).to eq(303)
    expect(browser.last_response.headers["location"]).to end_with("/protected")

    browser.get("/protected")
    expect(browser.last_response.status).to eq(200)
    expect(browser.last_response.body).to include(session.idk_b64, "Completed via: cps", "created on this login: true")

    browser.post("/logout")
    browser.get("/protected")
    expect(browser.last_response.status).to eq(403)
  end

  it "shows the failure page for a stale callback" do
    browser = new_browser
    browser.get("/auth/sqrl/callback")
    expect(browser.last_response.status).to eq(302)
    browser.get(request_uri(browser.last_response.headers["location"]))
    expect(browser.last_response.status).to eq(403)
    expect(browser.last_response.body).to include("invalid_credentials")
  end
end
