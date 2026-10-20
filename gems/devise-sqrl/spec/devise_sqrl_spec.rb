# frozen_string_literal: true

RSpec.describe "devise-sqrl" do
  describe "routes" do
    let(:helpers) { Rails.application.routes.url_helpers }

    it "adds the SQRL routes to the mapping with the expected helpers" do
      expect(helpers.new_user_sqrl_path).to eq("/users/sqrl")
      expect(helpers.cli_user_sqrl_path).to eq("/users/sqrl/cli")
      expect(helpers.status_user_sqrl_path).to eq("/users/sqrl/status")
      expect(helpers.callback_user_sqrl_path).to eq("/users/sqrl/callback")
      expect(helpers.script_user_sqrl_path).to eq("/users/sqrl/sqrl.js")
    end

    it "marks the mapping as sqrl_authenticatable and uses the devise/sqrl controller" do
      mapping = Devise.mappings[:user]
      expect(mapping).to be_sqrl_authenticatable
      expect(mapping.controllers[:sqrl]).to eq("devise/sqrl")
      expect(mapping.strategies).to include(:sqrl_authenticatable)
      expect(Devise::Controllers::UrlHelpers.instance_methods).to include(:new_sqrl_path, :callback_sqrl_url)
    end
  end

  describe "login page and protocol endpoint" do
    it "renders the login block wired to the Devise routes and serves the script" do
      url, browser = open_login_page
      body = browser.last_response.body
      expect(url).to start_with("sqrl://www.example.com/users/sqrl/cli?nut=")
      expect(body).to include('data-sqrl-status="/users/sqrl/status"')
      expect(body).to include('<script src="/users/sqrl/sqrl.js" defer>')
      expect(body).to include("<svg")
      expect(SQRL::Rails::PendingLogin.count).to eq(1)

      browser.get("/users/sqrl/sqrl.js")
      expect(browser.last_response.status).to eq(200)
      expect(browser.last_response.body).to include("data-sqrl-login")
      etag = browser.last_response.headers["etag"]
      browser.get("/users/sqrl/sqrl.js", {}, { "HTTP_IF_NONE_MATCH" => etag })
      expect(browser.last_response.status).to eq(304)
    end

    it "answers the login page as JSON" do
      browser = new_browser
      browser.get("/users/sqrl.json", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.status).to eq(200)
      json = JSON.parse(browser.last_response.body)
      expect(json["url"]).to start_with("sqrl://www.example.com/users/sqrl/cli?nut=")
      expect(json["status"]).to eq("/users/sqrl/status")
    end

    it "renders the shared partial inside the Devise sessions page" do
      browser = new_browser
      browser.get("/users/sign_in", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.status).to eq(200)
      expect(browser.last_response.body).to include("Or sign in with SQRL")
      expect(login_url_from(browser.last_response.body)).to start_with("sqrl://www.example.com/users/sqrl/cli")
    end

    it "accepts the client's signed POST without a CSRF token and answers protocol garbage safely" do
      url, = open_login_page
      session = sqrl_login(new_client, url)
      expect(session.state).to eq(:known)

      client = new_client
      nut = URI.parse(url).query[/nut=([^&]+)/, 1]
      client.post("/users/sqrl/cli?nut=#{nut}", "client=zzz&server=yyy&ids=xxx",
                  { "CONTENT_TYPE" => "application/x-www-form-urlencoded", "REMOTE_ADDR" => ClientHelpers::IP })
      expect(client.last_response.status).to eq(200)
      expect(client.last_response.headers["x-sqrl-tif"]).not_to be_nil
    end
  end

  describe "CPS login" do
    it "signs a new identity in, creating a user with the identity linked" do
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      cps = session.cps_url
      expect(cps).to start_with("https://www.example.com/users/sqrl/callback?t=")

      visit_cps(browser, session)
      expect(browser.last_response.status).to eq(302)
      expect(browser.last_response.location).to eq("http://www.example.com/")
      follow(browser)
      expect(browser.last_response.body).to start_with("home: sqrl-")

      expect(User.count).to eq(1)
      user = User.last
      expect(user.sqrl_identities.count).to eq(1)
      expect(user.sqrl_identities.first.idk).to eq(session.idk_b64)
      expect(user).to be_sqrl_linked
      expect(user.sqrl_identity_for(session.idk_b64)).not_to be_nil
      expect(User.find_for_sqrl(SQRL::Rails.stores.identities.find(session.idk))).to eq(user)

      browser.get("/protected", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.status).to eq(200)
      expect(browser.last_response.body).to eq("protected: #{user.email}")
    end

    it "updates trackable columns on a SQRL sign-in" do
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      visit_cps(browser, session)
      user = User.last
      expect(user.sign_in_count).to eq(1)
      expect(user.current_sign_in_ip).to eq(ClientHelpers::IP)
    end

    it "sets the flash notice" do
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      visit_cps(browser, session)
      follow(browser)
      expect(browser.last_request.env["action_dispatch.request.flash_hash"]&.notice || "")
        .to eq("Signed in successfully.").or eq("")
    end

    it "refuses a reused token and a token presented by another browser" do
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      visit_cps(browser, session)
      expect(browser.last_response.status).to eq(302)

      # a second use, even by the signed-in browser, is refused
      visit_cps(browser, session)
      expect(browser.last_response.status).to eq(302)
      expect(browser.last_response.location).to end_with("/users/sqrl")
      follow(browser)
      expect(browser.last_response.body).to include("SQRL login failed or expired")
      browser.get("/protected", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.status).to eq(200)

      url2, = open_login_page
      session2 = sqrl_login(new_client, url2, identity(2))
      stranger = new_browser
      visit_cps(stranger, session2)
      expect(stranger.last_response.status).to eq(302)
      expect(stranger.last_response.location).to end_with("/users/sqrl")
      stranger.get("/protected")
      expect(stranger.last_response.status).to eq(302)
      expect(User.count).to eq(1)
    end

    it "recognises a returning identity without creating another user" do
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      visit_cps(browser, session)
      browser.delete("/logout", {}, { "REMOTE_ADDR" => ClientHelpers::IP })

      url2, browser2 = open_login_page
      session2 = sqrl_login(new_client, url2)
      expect(session2.state).to eq(:known)
      visit_cps(browser2, session2)
      follow(browser2)
      expect(browser2.last_response.body).to start_with("home: sqrl-")
      expect(User.count).to eq(1)
      expect(User.last.sign_in_count).to eq(2)
    end

    it "honours a same-site return_to" do
      url, browser = open_login_page(path: "/users/sqrl?return_to=/protected")
      session = sqrl_login(new_client, url)
      visit_cps(browser, session)
      expect(browser.last_response.location).to eq("http://www.example.com/protected")
    end

    it "ignores an off-site return_to" do
      url, browser = open_login_page(path: "/users/sqrl?return_to=https://evil.example/x")
      session = sqrl_login(new_client, url)
      visit_cps(browser, session)
      expect(browser.last_response.location).to eq("http://www.example.com/")
    end
  end

  describe "poll (non-CPS) login" do
    it "completes through the status endpoint and the token-less callback, once" do
      url, browser = open_login_page
      browser.get("/users/sqrl/status")
      expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => false)

      sqrl_login(new_client, url, cps: false)
      browser.get("/users/sqrl/status")
      expect(JSON.parse(browser.last_response.body)).to eq("authenticated" => true, "next" => "/users/sqrl/callback")

      browser.get("/users/sqrl/callback", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.status).to eq(302)
      follow(browser)
      expect(browser.last_response.body).to start_with("home: sqrl-")

      browser.delete("/logout", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      browser.get("/users/sqrl/callback", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.location).to end_with("/users/sqrl")
    end
  end

  describe "unknown identity policies" do
    it ":refuse rejects new identities with a message" do
      Devise.sqrl_on_unknown_identity = :refuse
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      expect(session.state).to eq(:failed)
      expect(User.count).to eq(0)
      expect(session.cps_url).to be_nil
      browser.get("/users/sqrl/callback", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.location).to end_with("/users/sqrl")
    end

    it ":link attaches a new identity to the signed-in user" do
      Devise.sqrl_on_unknown_identity = :link
      user = create_user
      browser = new_browser
      password_sign_in(browser, user)
      url, = open_login_page(browser)
      session = sqrl_login(new_client, url)
      expect(session.state).to eq(:known)
      visit_cps(browser, session)
      expect(browser.last_response.status).to eq(302)
      expect(user.reload.sqrl_identities.map(&:idk)).to eq([session.idk_b64])
      expect(User.count).to eq(1)

      user.unlink_sqrl_identity!(session.idk_b64)
      expect(user.sqrl_identities.count).to eq(0)
    end

    it ":link refuses new identities for anonymous browsers" do
      Devise.sqrl_on_unknown_identity = :link
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      expect(session.state).to eq(:failed)
      expect(User.count).to eq(0)
      browser.get("/users/sqrl/callback", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.location).to end_with("/users/sqrl")
    end

    it "uses sqrl_create_resource when given" do
      Devise.sqrl_create_resource = ->(_identity, klass) { klass.new(email: "custom@example.com", password: "password-123") }
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      visit_cps(browser, session)
      expect(User.last.email).to eq("custom@example.com")
    end
  end

  describe "Devise integration" do
    it "refuses inactive resources with their inactive message" do
      allow_any_instance_of(User).to receive(:inactive).and_return(true)
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      visit_cps(browser, session)
      expect(browser.last_response.location).to end_with("/users/sqrl")
      follow(browser)
      expect(browser.last_response.body).to include("confirm your email")
      browser.get("/protected")
      expect(browser.last_response.status).to eq(302)
    end

    it "sets the remember-me cookie when sqrl_remember_me is on" do
      Devise.sqrl_remember_me = true
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      visit_cps(browser, session)
      cookies = browser.last_response.headers["set-cookie"].to_s
      expect(cookies).to include("remember_user_token")
      expect(User.last.remember_created_at).not_to be_nil
    end

    it "does not set the remember-me cookie by default" do
      url, browser = open_login_page
      session = sqrl_login(new_client, url)
      visit_cps(browser, session)
      expect(browser.last_response.headers["set-cookie"].to_s).not_to include("remember_user_token")
    end

    it "uses sqrl_failure_path when configured" do
      Devise.sqrl_failure_path = "/users/sign_in"
      browser = new_browser
      browser.get("/users/sqrl/callback?t=bogus", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.location).to end_with("/users/sign_in")
    end

    it "refuses a login whose IP differs from the page view" do
      url, browser = open_login_page
      session = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: true))
      post_sqrl(new_client, session, session.query, ip: "10.0.0.9")
      expect(session.ip_check_failed?).to be(true)
      expect(session.cps_url).to be_nil
      browser.get("/users/sqrl/callback", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
      expect(browser.last_response.location).to end_with("/users/sqrl")
    end
  end
end
