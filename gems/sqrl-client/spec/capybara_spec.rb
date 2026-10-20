# frozen_string_literal: true

# The Capybara helper is exercised with a minimal stand-in for a Capybara::Session so this
# gem's suite needs no browser; the repository's integration specs run it in Chromium.
RSpec.describe SQRL::Client::Capybara do
  let(:site) { start_site }

  FakePage = Struct.new(:transport, :current_url) do
    def html = @html ||= transport.get(current_url).body
    def current_path = URI.parse(current_url).path

    def visit(url)
      resp = transport.get(URI.join(current_url, url).to_s)
      self.current_url = resp.final_url
      @html = resp.body
    end
  end

  it "logs the browser in through CPS" do
    browser = SQRL::Client::Transport.new
    page = FakePage.new(browser, site.login_url)
    result = described_class.login(page, identity: ephemeral("cap"))
    expect(result).to be_authenticated
    expect(page.current_path).to eq("/welcome")
    expect(page.html).to include(result.idk)
  end

  it "runs account commands against the page's link" do
    browser = SQRL::Client::Transport.new
    page = FakePage.new(browser, site.login_url)
    id = ephemeral("cap2")
    described_class.login(page, identity: id)
    page.visit("/login")
    expect(described_class.command(page, :disable, identity: id).tif).to be_sqrl_disabled
    page.visit("/login")
    expect(described_class.command(page, :enable, identity: id)).to be_authenticated
    page.visit("/login")
    expect(described_class.command(page, :remove, identity: id).tif).not_to be_id_match
    expect { described_class.command(page, :bogus, identity: id) }.to raise_error(ArgumentError)
  end
end
