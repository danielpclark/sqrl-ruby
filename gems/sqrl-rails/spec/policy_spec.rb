# frozen_string_literal: true

RSpec.describe SQRL::Rails::PasswordPolicy do
  def login_with(flags)
    url, browser = open_login_page
    session = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: true, **flags))
    client = new_client
    post_sqrl(client, session, session.query)
    post_sqrl(client, session, session.ident)
    browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    user = User.last
    user.update!(email_address: "alice@example.com", password: "secret-password")
    user
  end

  it "exposes the policy flags of a user's identities" do
    user = login_with(sqrlonly: true, hardlock: false)
    expect(SQRL::Rails.sqrl_only?(user)).to be(true)
    expect(SQRL::Rails.hard_locked?(user)).to be(false)
    expect(SQRL::Rails::Identity.sqrl_only.count).to eq(1)
    expect(SQRL::Rails::Identity.hard_locked.count).to eq(0)
    expect(SQRL::Rails.sqrl_only?(nil)).to be(false)
    expect(SQRL::Rails.sqrl_only?(User.create!(name: "other"))).to be(false)
  end

  it "refuses password logins for sqrlonly users and allows them for others" do
    user = login_with(sqrlonly: true, hardlock: false)
    browser = new_browser
    browser.post("/session", { email_address: user.email_address, password: "secret-password" })
    expect(browser.last_response.status).to eq(302)
    expect(browser.last_response.location).to end_with("/session/new")
    follow(browser)
    expect(browser.last_response.body).to include("signs in with SQRL only")
    expect(user.sessions.count).to eq(1) # only the SQRL login

    other = User.create!(name: "bob", email_address: "bob@example.com", password: "pw")
    browser = new_browser
    browser.post("/session", { email_address: "bob@example.com", password: "pw" })
    expect(browser.last_response.location).to eq("http://www.example.com/")
    expect(other.sessions.count).to eq(1)
  end

  it "refuses password resets for hard-locked users at every step" do
    user = login_with(sqrlonly: false, hardlock: true)
    browser = new_browser
    browser.post("/passwords", { email_address: user.email_address })
    expect(browser.last_response.status).to eq(302)
    follow(browser)
    expect(browser.last_response.body).to include("Password recovery is disabled")

    token = user.generate_token_for(:password_reset)
    browser.get("/passwords/#{token}/edit")
    expect(browser.last_response.status).to eq(302)
    browser.patch("/passwords/#{token}", { password: "new" })
    expect(browser.last_response.status).to eq(302)
    expect(user.reload.authenticate("new")).to be_falsey

    # a user without the flag is not affected
    other = User.create!(name: "bob", email_address: "bob@example.com", password: "pw")
    browser.post("/passwords", { email_address: "bob@example.com" })
    expect(browser.last_response.body).to eq("reset mail sent")
    browser.patch("/passwords/#{other.generate_token_for(:password_reset)}", { password: "new" })
    expect(browser.last_response.body).to eq("password reset")
  end
end
