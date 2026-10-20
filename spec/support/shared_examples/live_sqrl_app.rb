# frozen_string_literal: true

require "capybara"
require_relative "../integration_helpers"
require_relative "../browser"

# The behaviour every example application must show, driven by the bot client, the
# conformance suite and a headless browser. Include "live example app" first.
RSpec.shared_examples "a live SQRL example app" do
  describe "conformance suite" do
    let(:conformance_features) { descriptor.features }
    let(:conformance_options) { { site: site, transport_factory: -> { new_transport } } }

    it_behaves_like "a SQRL server"
  end

  describe "bot client flows" do
    it "creates an account on the first login and lands on a logged-in page" do
      agent = new_agent(ephemeral)
      result = login_via_site(agent)
      expect(result).to be_created
      expect_logged_in(result)
      expect(protected_status(agent.http)).to eq(200)
    end

    it "refuses the protected page to a browser that has not logged in" do
      expect(protected_status(new_transport)).to eq(descriptor.anonymous_protected_status)
    end

    it "recognises the same identity from a second browser without creating another account" do
      id = ephemeral
      login_via_site(new_agent(id))
      second = new_agent(id)
      result = login_via_site(second)
      expect(result).not_to be_created
      expect(result.state).to be_known
      expect_logged_in(result)
      expect(protected_status(second.http)).to eq(200)
    end

    it "disables, refuses login while disabled, re-enables with the IUK and logs in again" do
      id = ephemeral
      login_via_site(new_agent(id))
      disable = new_agent(id, cps: false, poll: false).disable(site.login_page(new_transport).sqrl_url)
      expect(disable.tif).to be_sqrl_disabled
      expect { login_via_site(new_agent(id)) }.to raise_error(SQRL::Client::LoginFailed) { |e| expect(e.reason).to eq(:disabled) }

      enable_agent = new_agent(id)
      enable = enable_agent.enable(site.login_page(enable_agent.http).sqrl_url)
      expect_logged_in(enable)
      expect(login_via_site(new_agent(id))).to be_authenticated
    end

    it "removes the association so the next login creates the account again" do
      id = ephemeral
      login_via_site(new_agent(id))
      remove = new_agent(id, cps: false, poll: false).remove(site.login_page(new_transport).sqrl_url)
      expect(remove.tif).not_to be_id_match
      expect(new_agent(id).query(site.login_page(new_transport).sqrl_url).state).to be_unknown
      expect(login_via_site(new_agent(id))).to be_created
    end

    it "moves the account to a re-keyed identity and refuses the superseded one" do
      id = ephemeral
      first = login_via_site(new_agent(id))
      id.rekey!
      rekeyed = login_via_site(new_agent(id))
      expect(rekeyed).to be_rekeyed
      expect(rekeyed.idk).not_to eq(first.idk)
      expect_logged_in(rekeyed)
      expect(login_via_site(new_agent(id))).not_to be_rekeyed
      old = id.previous_identity
      expect { login_via_site(new_agent(old)) }.to raise_error(SQRL::Client::LoginFailed) { |e| expect(e.reason).to eq(:superseded) }
    end
  end

  describe "in a headless browser", :browser do
    before(:all) do
      Capybara.run_server = false
      @browser = Capybara::Session.new(:sqrl_cuprite)
    end

    after(:all) { @browser&.quit }
    after { @browser.reset! }

    let(:page) { @browser }

    def open_login_page
      if descriptor.browser_login
        descriptor.browser_login.call(page, app)
      else
        page.visit(app.url(descriptor.login_path))
      end
      expect(page).to have_css("[data-sqrl-login][data-sqrl-initialized]", wait: 10)
    end

    def expect_browser_logged_in
      expect(page).to have_current_path(%r{\A(?!.*(login|sign_in|session/new|auth/sqrl)).*}, wait: 10)
      expect(descriptor.logged_in.call(page.html)).to be(true),
                                                      "browser did not land on a logged-in page: #{page.current_url}\n#{page.html[0,
                                                                                                                                  400]}"
    end

    it "renders the login block, initialises sqrl.js and keeps the direct link when no local client answers" do
      open_login_page
      link = page.find("a[data-sqrl-link]")
      # Real SQRL: sqrl:// (HTTPS). qrl:// is the browser extension's plain-http test mode only.
      expect(link[:href]).to match(%r{\Asqrl://127\.0\.0\.1:#{app.port}/})
      expect(page).to have_css("[data-sqrl-login] svg[role='img']")
      expect(page).to have_css("a[data-sqrl-link][data-sqrl-cps='false']", wait: 10)
      expect(page).to have_css("[data-sqrl-message]")
    end

    it "logs the browser in through the CPS handoff" do
      open_login_page
      result = SQRL::Client::Capybara.login(page, identity: ephemeral, transport: new_transport)
      expect(result).to be_authenticated
      expect_browser_logged_in
      page.visit(app.url(descriptor.protected_path))
      expect(page.status_code).to eq(200)
      expect(descriptor.logged_in.call(page.html)).to be(true)

      if descriptor.logout
        page.visit(app.url(descriptor.home_path))
        page.click_button(descriptor.logout[:text])
        page.visit(app.url(descriptor.protected_path))
        expect_browser_anonymous(page)
      end
    end

    it "completes a non-CPS login through the page's own poller" do
      open_login_page
      result = SQRL::Client::Capybara.login(page, identity: ephemeral, cps: false, wait: 15, transport: new_transport)
      expect(result).to be_authenticated
      expect(result.cps_url).to be_nil
      expect_browser_logged_in
    end

    it "offers a cancel link back to the site" do
      skip "this example's login block has no cancel link" unless descriptor.cancel
      open_login_page
      page.click_link("Cancel")
      expect(page).to have_current_path(descriptor.home_path)
    end
  end
end
