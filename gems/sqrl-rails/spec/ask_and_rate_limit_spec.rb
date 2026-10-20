# frozen_string_literal: true

RSpec.describe "ask, deny button and rate limiting" do
  before do
    SQRL::Rails.config.ask = SQRL::Ask.new(message: "Allow?", buttons: [{ label: "Allow" }, { label: "Deny" }])
    SQRL::Rails.config.ask_deny_button = 2
  end

  def login_answering(browser, button)
    url, = open_login_page(browser)
    client = new_client
    session = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: true))
    post_sqrl(client, session, session.query)
    # first login: unknown identity, no ask; create the account
    post_sqrl(client, session, session.ident)
    browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    browser.delete("/session")

    url, = open_login_page(browser)
    session = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: true))
    post_sqrl(client, session, session.query)
    expect(session.pending_ask&.message).to eq("Allow?")
    session.set_button(button)
    post_sqrl(client, session, session.query)
    post_sqrl(client, session, session.ident)
    expect(session.state).to eq(:known)
    browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    browser
  end

  it "completes the login when the allow button is pressed" do
    browser = login_answering(new_browser, 1)
    expect(browser.last_response.location).to eq("http://www.example.com/")
    follow(browser)
    expect(browser.last_response.body).to start_with("home: SQRL user")
  end

  it "refuses the login when the deny button is pressed" do
    browser = login_answering(new_browser, 2)
    expect(browser.last_response.location).to end_with("/sqrl/login")
    follow(browser)
    expect(browser.last_response.body).to include("declined")
    browser.get("/protected")
    expect(browser.last_response.status).to eq(302)
  end

  it "rate limits the protocol endpoint and the login page per IP" do
    cache = ActiveSupport::Cache::MemoryStore.new
    SQRL::Rails.config.rate_limit = { to: 2, within: 60, cache: cache }
    client = new_client
    3.times { client.post("/sqrl/cli?nut=x", "", { "REMOTE_ADDR" => "203.0.113.7" }) }
    expect(client.last_response.status).to eq(429)
    expect(client.last_response.headers["retry-after"]).not_to be_nil
    # another IP is unaffected
    client.post("/sqrl/cli?nut=x", "", { "REMOTE_ADDR" => "203.0.113.8" })
    expect(client.last_response.status).to eq(200)

    browser = new_browser
    3.times { browser.get("/sqrl/login", {}, { "REMOTE_ADDR" => "203.0.113.9" }) }
    expect(browser.last_response.status).to eq(429)

    SQRL::Rails.config.rate_limit = { to: 1, within: 60, cache: cache, only: [:login] }
    client.post("/sqrl/cli?nut=x", "", { "REMOTE_ADDR" => "203.0.113.10" })
    client.post("/sqrl/cli?nut=x", "", { "REMOTE_ADDR" => "203.0.113.10" })
    expect(client.last_response.status).to eq(200)
  end
end

RSpec.describe "refresh endpoint, hooks and host handling" do
  it "serves a fresh login URL as JSON and advertises the refresh URL in the login block" do
    url, browser = open_login_page
    expect(browser.last_response.body).to include('data-sqrl-refresh="/sqrl/refresh"')
    browser.get("/sqrl/refresh", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    expect(browser.last_response.status).to eq(200)
    json = JSON.parse(browser.last_response.body)
    expect(json["sqrl_url"]).to start_with("sqrl://www.example.com/sqrl/cli?nut=")
    expect(json["sqrl_url"]).not_to eq(url)
    expect(json["status_url"]).to eq("/sqrl/status")
    expect(json["qr_svg"]).to include("<svg")
    # the fresh URL works
    session = sqrl_login(new_client, json["sqrl_url"])
    expect(session.state).to eq(:known)
    expect(SQRL::Rails::PendingLogin.count).to eq(2)
  end

  it "answers 429 when a before_handle / before_issue hook raises RateLimited" do
    SQRL::Rails.config.before_handle = ->(_ctx) { raise SQRL::Server::RateLimited.new("slow down", retry_after: 7) }
    url, = open_login_page
    client = new_client
    session = SQRL::Session.new(identity, url)
    req = session.query
    uri = URI.parse(req.url)
    client.post("#{uri.path}?#{uri.query}", req.body, { "CONTENT_TYPE" => "application/x-www-form-urlencoded" })
    expect(client.last_response.status).to eq(429)
    expect(client.last_response.headers["retry-after"]).to eq("7")

    SQRL::Rails.config.before_handle = nil
    SQRL::Rails.config.before_issue = ->(_ctx) { raise SQRL::Server::RateLimited, "no more pages" }
    SQRL::Rails.reset!
    browser = new_browser
    browser.get("/sqrl/login")
    expect(browser.last_response.status).to eq(429)
    browser.get("/sqrl/refresh")
    expect(browser.last_response.status).to eq(429)
    expect(JSON.parse(browser.last_response.body)["error"]).to eq("rate_limited")
  end

  it "refuses hosts outside allowed_hosts and bounds the derived-host cache" do
    SQRL::Rails.config.allowed_hosts = ["www.example.com"]
    SQRL::Rails.reset!
    browser = new_browser
    browser.get("/sqrl/login")
    expect(browser.last_response.status).to eq(200)
    browser.get("/sqrl/login", {}, { "HTTP_HOST" => "evil.example" })
    expect(browser.last_response.status).to eq(400)

    SQRL::Rails.config.allowed_hosts = nil
    SQRL::Rails.config.host_cache_limit = 2
    SQRL::Rails.reset!
    %w[a.example b.example].each do |h|
      browser.get("/sqrl/login", {}, { "HTTP_HOST" => h })
      expect(browser.last_response.status).to eq(200)
    end
    browser.get("/sqrl/login", {}, { "HTTP_HOST" => "c.example" })
    expect(browser.last_response.status).to eq(400)
    expect(SQRL::Rails.host_resolver.known_hosts).to contain_exactly("a.example", "b.example")
  end
end
