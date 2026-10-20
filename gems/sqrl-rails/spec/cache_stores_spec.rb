# frozen_string_literal: true

RSpec.describe SQRL::Rails::Stores::Cache do
  let(:cache) { ActiveSupport::Cache::MemoryStore.new }
  let(:stores) { described_class.stores(cache) }

  it_behaves_like "a SQRL store set"

  it "refuses process-local stores in production unless told otherwise" do
    allow(Rails).to receive(:env).and_return(ActiveSupport::EnvironmentInquirer.new("production"))
    expect { described_class.stores(ActiveSupport::Cache::MemoryStore.new) }.to raise_error(SQRL::Rails::Error, /process-local/)
    expect { described_class.stores(ActiveSupport::Cache::MemoryStore.new, allow_unsafe: true) }.not_to raise_error
    expect { described_class.stores(Object.new) }.to raise_error(SQRL::Rails::Error, /Cache::Store/)
  end

  it "is selectable through config.sqrl.stores = :cache and runs a full login" do
    SQRL::Rails.config.stores = :cache
    SQRL::Rails.config.cache_store = cache
    SQRL::Rails.reset!
    expect(SQRL::Rails.stores.nuts).to be_a(described_class::NutStore)

    url, browser = open_login_page
    session = sqrl_login(new_client, url)
    expect(session.state).to eq(:known)
    browser.get(URI.parse(session.cps_url).request_uri, {}, { "REMOTE_ADDR" => ClientHelpers::IP })
    expect(browser.last_response.status).to eq(302)
    follow(browser)
    expect(browser.last_response.body).to start_with("home: SQRL user")
    expect(SQRL::Rails::Identity.count).to eq(0) # identities live in the cache
    expect(stores.identities.find(session.idk)).not_to be_nil
  end
end
