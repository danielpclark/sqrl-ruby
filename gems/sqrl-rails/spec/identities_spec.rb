# frozen_string_literal: true

RSpec.describe "SQRL::Rails identity management" do
  def sign_in_with_sqrl(browser, id)
    url, = open_login_page(browser)
    session = sqrl_login(new_client, url, id)
    browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    session
  end

  it "requires a signed-in user" do
    browser = new_browser
    browser.get("/sqrl/identities")
    expect(browser.last_response.status).to eq(302)
    expect(browser.last_response.location).to end_with("/session/new")
  end

  it "lists the user's identities and unlinks one" do
    browser = new_browser
    first = sign_in_with_sqrl(browser, identity(1))
    user = User.last
    # link a second identity to the same user
    SQRL::Rails.config.on_unknown_identity = :link
    second = sign_in_with_sqrl(browser, identity(2))
    SQRL::Rails.config.on_unknown_identity = :create
    expect(user.sqrl_identities.count).to eq(2)

    browser.get("/sqrl/identities")
    expect(browser.last_response.status).to eq(200)
    body = browser.last_response.body
    expect(body).to include(%(data-sqrl-idk="#{first.idk_b64}"), %(data-sqrl-idk="#{second.idk_b64}"))
    expect(body).to include("(this session)")
    expect(body.scan(">Unlink</button>").size).to eq(2)
    expect(SQRL::Rails::Identity.active.first.last_login_at).not_to be_nil

    row = SQRL::Rails::Identity.active.find_by(idk: first.idk_b64)
    browser.delete("/sqrl/identities/#{row.id}")
    expect(browser.last_response.status).to eq(303)
    expect(user.sqrl_identities.count).to eq(1)
    expect(row.reload.user).to be_nil
    follow(browser)
    expect(browser.last_response.body).to include("unlinked")

    # unknown ids are reported, nothing else changes
    browser.delete("/sqrl/identities/999999")
    follow(browser)
    expect(browser.last_response.body).to include("not linked")
    expect(user.sqrl_identities.count).to eq(1)
  end

  it "keeps logins and last_login_at current" do
    browser = new_browser
    sign_in_with_sqrl(browser, identity(3))
    row = SQRL::Rails::Identity.active.last
    expect(row.logins).to eq(1)
    first_login = row.last_login_at
    sleep 0.01
    other = new_browser
    sign_in_with_sqrl(other, identity(3))
    row.reload
    expect(row.logins).to eq(2)
    expect(row.last_login_at).to be >= first_login
  end
end
