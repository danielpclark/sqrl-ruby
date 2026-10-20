# frozen_string_literal: true

RSpec.describe "SQRL::Rails engine" do
  it "renders the login block in the host's sign-in page and serves the script" do
    url, browser = open_login_page
    body = browser.last_response.body
    expect(url).to start_with("sqrl://www.example.com/sqrl/cli?nut=")
    expect(body).to include('data-sqrl-status="/sqrl/status"')
    expect(body).to include('<script src="/sqrl/sqrl.js" defer>')
    expect(body).to include("<svg")
    expect(SQRL::Rails::PendingLogin.count).to eq(1)

    browser.get("/sqrl/sqrl.js")
    expect(browser.last_response.status).to eq(200)
    expect(browser.last_response.body).to include("data-sqrl-login")
    etag = browser.last_response.headers["etag"]
    browser.get("/sqrl/sqrl.js", {}, { "HTTP_IF_NONE_MATCH" => etag })
    expect(browser.last_response.status).to eq(304)
  end

  it "serves the stand-alone login page" do
    browser = new_browser
    browser.get("/sqrl/login")
    expect(browser.last_response.status).to eq(200)
    expect(browser.last_response.body).to include("Sign in with SQRL")
    expect(login_url_from(browser.last_response.body)).to start_with("sqrl://")
  end

  it "logs a new identity in through CPS, creating a user and a Rails 8 session" do
    url, browser = open_login_page
    client = new_client
    session = sqrl_login(client, url)
    expect(session.state).to eq(:known)
    cps = session.cps_url
    expect(cps).to start_with("https://www.example.com/sqrl/callback?t=")

    browser.get(URI.parse(cps).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    expect(browser.last_response.status).to eq(302)
    expect(browser.last_response.location).to eq("http://www.example.com/")
    follow(browser)
    expect(browser.last_response.body).to start_with("home: SQRL user")

    user = User.last
    expect(User.count).to eq(1)
    expect(user.sessions.count).to eq(1)
    expect(user.sqrl_identities.count).to eq(1)
    expect(user.sqrl_identities.first.idk).to eq(session.idk_b64)

    browser.get("/protected")
    expect(browser.last_response.status).to eq(200)
    expect(browser.last_response.body).to eq("protected: #{user.name}")

    # the CPS token is single use
    browser2 = new_browser
    browser2.get(URI.parse(cps).request_uri)
    expect(browser2.last_response.status).to eq(302)
    expect(browser2.last_response.location).to end_with("/sqrl/login")
  end

  it "refuses a CPS token presented by a different browser session" do
    url, = open_login_page
    session = sqrl_login(new_client, url)
    stranger = new_browser
    stranger.get(URI.parse(session.cps_url).request_uri)
    expect(stranger.last_response.status).to eq(302)
    expect(stranger.last_response.location).to end_with("/sqrl/login")
    expect(User.count).to eq(0)
    follow(stranger)
    expect(stranger.last_response.body).to include("SQRL login failed or expired")
  end

  it "completes a non-CPS login through the poll endpoint" do
    url, browser = open_login_page
    browser.get("/sqrl/status")
    expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => false)

    sqrl_login(new_client, url, cps: false)
    browser.get("/sqrl/status")
    status = JSON.parse(browser.last_response.body)
    expect(status).to eq("authenticated" => true, "next" => "/sqrl/callback")

    browser.get("/sqrl/callback", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    expect(browser.last_response.status).to eq(302)
    follow(browser)
    expect(browser.last_response.body).to start_with("home: SQRL user")
    expect(User.count).to eq(1)

    # a second completion of the same pending login fails
    browser.get("/sqrl/callback")
    expect(browser.last_response.location).to end_with("/sqrl/login")
  end

  it "logs an existing identity in again without creating another user" do
    url, browser = open_login_page
    session = sqrl_login(new_client, url)
    browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    expect(User.count).to eq(1)

    other = new_browser
    url2, = open_login_page(other)
    session2 = sqrl_login(new_client, url2)
    expect(session2.state).to eq(:known)
    other.get(URI.parse(session2.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    follow(other)
    expect(other.last_response.body).to start_with("home: SQRL user")
    expect(User.count).to eq(1)
    expect(SQRL::Rails::Identity.active.first.logins).to eq(2)
  end

  it "honours return_to from the pending login" do
    browser = new_browser
    url, = open_login_page(browser, path: "/session/new?return_to=/protected")
    session = sqrl_login(new_client, url)
    browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    expect(browser.last_response.location).to eq("http://www.example.com/protected")
  end

  it "uses the host's return_to_after_authenticating when a protected page redirected to sign in" do
    browser = new_browser
    browser.get("/protected", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    expect(browser.last_response.status).to eq(302)
    url, = open_login_page(browser)
    session = sqrl_login(new_client, url)
    browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    expect(browser.last_response.location).to eq("http://www.example.com/protected")
  end

  context "when on_unknown_identity is :refuse" do
    before { SQRL::Rails.config.on_unknown_identity = :refuse }

    it "does not create an account" do
      url, = open_login_page
      client = new_client
      session = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: true))
      post_sqrl(client, session, session.query)
      post_sqrl(client, session, session.ident)
      expect(session.state).to eq(:failed)
      expect(session.last_response.tif).to be_command_failed
      expect(User.count).to eq(0)
      expect(SQRL::Rails::Identity.count).to eq(0)
    end
  end

  context "when on_unknown_identity is :link" do
    before { SQRL::Rails.config.on_unknown_identity = :link }

    it "attaches a new identity to the signed-in user and rejects anonymous creation" do
      # anonymous: creation refused by the protocol
      url, = open_login_page
      client = new_client
      session = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: true))
      post_sqrl(client, session, session.query)
      post_sqrl(client, session, session.ident)
      expect(session.last_response.tif).to be_command_failed

      # signed in through the host's own session: the login page carries the link ref
      user = User.create!(name: "Alice")
      browser = new_browser
      SQRL::Rails.config.sign_in = ->(controller, _identity, u) { controller.send(:start_new_session_for, u) }
      # sign Alice in by hand (as the host app would)
      app_session = user.sessions.create!(ip_address: ClientHelpers::IP, user_agent: "spec")
      jar = ActionDispatch::Cookies::CookieJar.build(ActionDispatch::TestRequest.create, {})
      jar.signed[:session_id] = app_session.id
      browser.set_cookie("session_id=#{jar[:session_id]}")

      url, = open_login_page(browser)
      pending = SQRL::Rails::PendingLogin.last
      expect(pending.link_user_ref).to eq("User:#{user.id}")
      session = sqrl_login(new_client, url, identity(2))
      expect(session.state).to eq(:known)
      browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.status).to eq(302)
      expect(User.count).to eq(1)
      expect(user.sqrl_identities.count).to eq(1)
    end
  end

  it "lets the application supply its own sign_in, find_user and create_user" do
    calls = []
    SQRL::Rails.config.create_user = lambda { |identity|
      calls << [:create, identity.idk_b64]
      User.create!(name: "custom")
    }
    SQRL::Rails.config.sign_in = lambda { |controller, identity, user|
      calls << [:sign_in, identity.idk_b64, user.name]
      controller.session[:custom_user] = user.id
    }
    SQRL::Rails.config.after_sign_in = ->(_controller, _completion) { "/protected" }

    url, browser = open_login_page
    session = sqrl_login(new_client, url)
    browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    expect(browser.last_response.location).to eq("http://www.example.com/protected")
    expect(calls.map(&:first)).to eq(%i[create sign_in])
    expect(calls.last.last).to eq("custom")
    expect(User.last.sessions.count).to eq(0)
  end

  it "rejects a login when the request IP differs from the login page's IP" do
    url, = open_login_page
    client = new_client
    session = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: true))
    post_sqrl(client, session, session.query, ip: "203.0.113.9")
    expect(session.ip_check_failed?).to be(true)
  end

  it "answers protocol garbage with a protocol failure, never an exception" do
    client = new_client
    client.post("/sqrl/cli?nut=bogus", "client=x&server=y&ids=z", { "CONTENT_TYPE" => "application/x-www-form-urlencoded" })
    expect(client.last_response.status).to eq(200)
    response = SQRL::ServerResponse.parse(client.last_response.body)
    expect(response.tif).to be_transient_error
  end

  it "exposes controller helpers to the host application" do
    url, browser = open_login_page
    session = sqrl_login(new_client, url)
    browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    controller = ApplicationController.new
    expect(controller).to respond_to(:current_sqrl_identity)
    expect(controller).to respond_to(:sqrl_logout!)
    browser.delete("/session")
    expect(browser.last_response.status).to eq(303)
    browser.get("/protected")
    expect(browser.last_response.status).to eq(302)
  end

  it "detects the mount path and builds public paths" do
    expect(SQRL::Rails.mount_path).to eq("/sqrl")
    expect(SQRL::Rails.path_for(:cli)).to eq("/sqrl/cli")
    expect(SQRL::Rails.path_for(:callback, script_name: "/app")).to eq("/app/sqrl/callback")
    expect(SQRL::Rails.user_ref(User.create!(name: "x"))).to match(/\AUser:\d+\z/)
    expect(SQRL::Rails.user_from_ref("User:999999")).to be_nil
    expect(SQRL::Rails.user_from_ref("Nope:1")).to be_nil
    expect(SQRL::Rails.user_from_ref(nil)).to be_nil
    expect(SQRL::Rails.host_authentication_concern).to eq(Authentication)
  end
end
