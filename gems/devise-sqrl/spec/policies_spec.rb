# frozen_string_literal: true

RSpec.describe "devise-sqrl account policies and identity management" do
  # Log a fresh identity in through CPS with the given opt flags; returns [user, session].
  def sqrl_user(browser, id = identity, **flags)
    url, = open_login_page(browser)
    session = SQRL::Session.new(id, url, options: SQRL::ClientOptions.new(cps: true, **flags))
    client = new_client
    post_sqrl(client, session, session.query)
    post_sqrl(client, session, session.ident)
    visit_cps(browser, session)
    [User.last, session]
  end

  def set_password(user, password)
    user.update!(password: password, password_confirmation: password)
  end

  describe "sqrlonly" do
    it "refuses password logins for sqrl-only users but not for others" do
      browser = new_browser
      user, = sqrl_user(browser, identity(1), sqrlonly: true)
      set_password(user, "secret-password")
      expect(user).to be_sqrl_only
      browser.delete("/logout")

      browser.post("/users/sign_in", { user: { email: user.email, password: "secret-password" } })
      expect(browser.last_response.status).to eq(302)
      expect(browser.last_response.location).to end_with("/users/sign_in")
      follow(browser)
      expect(browser.last_response.body).to include("signs in with SQRL only")
      browser.get("/protected")
      expect(browser.last_response.status).to eq(302)

      other = User.create!(email: "bob@example.com", password: "pw-pw-pw", password_confirmation: "pw-pw-pw")
      browser = new_browser
      browser.post("/users/sign_in", { user: { email: other.email, password: "pw-pw-pw" } })
      expect(browser.last_response.location).to eq("http://www.example.com/")
      browser.get("/protected")
      expect(browser.last_response.status).to eq(200)
    end

    it "still lets a sqrl-only user sign in with SQRL and restores the session from the cookie" do
      browser = new_browser
      user, = sqrl_user(browser, identity(2), sqrlonly: true)
      browser.get("/protected")
      expect(browser.last_response.status).to eq(200)
      expect(browser.last_response.body).to eq("protected: #{user.email}")
    end

    it "can be told which strategies to block" do
      Devise.sqrl_only_blocked_strategies = []
      browser = new_browser
      user, = sqrl_user(browser, identity(3), sqrlonly: true)
      set_password(user, "secret-password")
      browser.delete("/logout")
      browser.post("/users/sign_in", { user: { email: user.email, password: "secret-password" } })
      expect(browser.last_response.location).to eq("http://www.example.com/")
    end
  end

  describe "hardlock" do
    it "refuses password reset instructions and token resets for hard-locked users" do
      browser = new_browser
      user, = sqrl_user(browser, identity(4), hardlock: true)
      set_password(user, "secret-password")
      expect(user).to be_hard_locked
      expect(user).not_to be_sqrl_only

      expect { User.send_reset_password_instructions(email: user.email) }.not_to(change { ActionMailer::Base.deliveries.size })
      record = User.send_reset_password_instructions(email: user.email)
      expect(record.errors[:base].join).to include("Password recovery is disabled")

      token = user.send(:set_reset_password_token)
      reset = User.reset_password_by_token(reset_password_token: token, password: "new-password-1",
                                           password_confirmation: "new-password-1")
      expect(reset.errors[:base].join).to include("Password recovery is disabled")
      expect(user.reload.valid_password?("new-password-1")).to be(false)

      # through the controller as well
      browser.post("/users/password", { user: { email: user.email } })
      expect(browser.last_response.body).to include("Password recovery is disabled")

      other = User.create!(email: "bob@example.com", password: "pw-pw-pw", password_confirmation: "pw-pw-pw")
      expect { User.send_reset_password_instructions(email: other.email) }.to change { ActionMailer::Base.deliveries.size }.by(1)
    end
  end

  describe "ask with a deny button" do
    before do
      SQRL::Rails.config.ask = SQRL::Ask.new(message: "Allow?", buttons: [{ label: "Allow" }, { label: "Deny" }])
      SQRL::Rails.config.ask_deny_button = 2
    end

    def answer(browser, button)
      url, = open_login_page(browser)
      client = new_client
      session = SQRL::Session.new(identity(5), url, options: SQRL::ClientOptions.new(cps: true))
      post_sqrl(client, session, session.query)
      expect(session.pending_ask&.message).to eq("Allow?")
      session.set_button(button)
      post_sqrl(client, session, session.query)
      post_sqrl(client, session, session.ident)
      visit_cps(browser, session)
      browser
    end

    it "accepts the allow button and refuses the deny button" do
      browser = new_browser
      sqrl_user(browser, identity(5)) # account creation poses no ask
      browser.delete("/logout")

      answer(browser, 1)
      expect(browser.last_response.location).to eq("http://www.example.com/")

      browser.delete("/logout")
      answer(browser, 2)
      expect(browser.last_response.location).to end_with("/users/sqrl")
      follow(browser)
      expect(browser.last_response.body).to include("declined")
      browser.get("/protected")
      expect(browser.last_response.status).to eq(302)
    end
  end

  describe "identity management" do
    it "requires a signed-in resource" do
      browser = new_browser
      browser.get("/users/sqrl/identities")
      expect(browser.last_response.status).to eq(302)
      expect(browser.last_response.location).to end_with("/users/sign_in")
    end

    it "lists the resource's identities and unlinks one" do
      browser = new_browser
      user, first = sqrl_user(browser, identity(6))
      Devise.sqrl_on_unknown_identity = :link
      _, second = sqrl_user(browser, identity(7))
      Devise.sqrl_on_unknown_identity = nil
      expect(user.sqrl_identities.count).to eq(2)

      browser.get("/users/sqrl/identities")
      expect(browser.last_response.status).to eq(200)
      body = browser.last_response.body
      expect(body).to include(%(data-sqrl-idk="#{first.idk_b64}"), %(data-sqrl-idk="#{second.idk_b64}"))
      expect(body.scan(">Unlink</button>").size).to eq(2)

      row = user.sqrl_identities.find_by(idk: first.idk_b64)
      browser.delete("/users/sqrl/identities/#{row.id}")
      expect(browser.last_response.status).to eq(303)
      expect(user.sqrl_identities.count).to eq(1)
      expect(row.reload.user).to be_nil
      follow(browser)
      expect(browser.last_response.body).to include("unlinked")

      browser.delete("/users/sqrl/identities/999999")
      follow(browser)
      expect(browser.last_response.body).to include("not linked")
      expect(helpers_paths).to include("/users/sqrl/identities")
    end

    def helpers_paths
      h = Rails.application.routes.url_helpers
      [h.identities_user_sqrl_path, h.unlink_identity_user_sqrl_path(1)]
    end
  end
end

RSpec.describe "devise-sqrl refresh, hooks and host handling" do
  it "serves a fresh login URL under the mapping and advertises it in the login block" do
    url, browser = open_login_page
    expect(browser.last_response.body).to include('data-sqrl-refresh="/users/sqrl/refresh"')
    browser.get("/users/sqrl/refresh", {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    expect(browser.last_response.status).to eq(200)
    json = JSON.parse(browser.last_response.body)
    expect(json["sqrl_url"]).to start_with("sqrl://www.example.com/users/sqrl/cli?nut=")
    expect(json["sqrl_url"]).not_to eq(url)
    expect(Rails.application.routes.url_helpers.refresh_user_sqrl_path).to eq("/users/sqrl/refresh")
    expect(sqrl_login(new_client, json["sqrl_url"]).state).to eq(:known)
  end

  it "answers 429 when a hook raises RateLimited and 400 for a disallowed host" do
    SQRL::Rails.config.before_handle = ->(_ctx) { raise SQRL::Server::RateLimited.new("slow down", retry_after: 3) }
    Devise::SQRL.reset!
    url, = open_login_page
    client = new_client
    session = SQRL::Session.new(identity, url)
    req = session.query
    uri = URI.parse(req.url)
    client.post("#{uri.path}?#{uri.query}", req.body, { "CONTENT_TYPE" => "application/x-www-form-urlencoded" })
    expect(client.last_response.status).to eq(429)
    expect(client.last_response.headers["retry-after"]).to eq("3")
    SQRL::Rails.config.before_handle = nil

    SQRL::Rails.config.allowed_hosts = ["www.example.com"]
    Devise::SQRL.reset!
    browser = new_browser
    browser.get("/users/sqrl", {}, { "HTTP_HOST" => "evil.example" })
    expect(browser.last_response.status).to eq(400)
  end
end
