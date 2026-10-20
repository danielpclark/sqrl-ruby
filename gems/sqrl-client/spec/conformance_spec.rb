# frozen_string_literal: true

require "sqrl/client/conformance"
require "sqrl/client/conformance/rspec"

RSpec.describe SQRL::Client::Conformance do
  describe SQRL::Client::Conformance::Runner do
    it "passes every case against the test site (ask and sin on)" do
      site = start_site(ask: SQRL::Ask.new(message: "Allow?", buttons: [{ label: "Yes" }, { label: "No" }]), sin: "0")
      report = described_class.new(login_url: site.login_url, features: { ask: true, sin: true }, insecure: true).run
      expect(report.failed.map { |c| [c.name, c.message] }).to eq([])
      expect(report.skipped).to be_empty
      expect(report).to be_passed
      expect(report.cases.size).to eq(described_class::CASES.size)
      expect(report.to_s).to include("PASS  happy/create_account", "passed, 0 failed")
      expect(report.to_junit_xml).to include("<testsuite", "tests=\"#{described_class::CASES.size}\"")
      expect(report.to_h[:cases].first).to include(status: :passed)
    end

    it "skips cases whose feature is off and runs only the requested ones" do
      site = start_site
      runner = described_class.new(login_url: site.login_url, features: { remove: false }, insecure: true,
                                   only: %i[create_account remove_then_recreate])
      report = runner.run
      expect(report.cases.map(&:status)).to eq(%i[passed skipped])
      expect(report).to be_passed
    end

    it "fails cases when the server misbehaves" do
      site = start_site
      # a site that never sends url= although the client asked for CPS
      site.config.cps_url = ->(_token, _login) { "https://elsewhere.example/landing" }
      report = described_class.new(login_url: site.login_url, only: %i[create_account login_cps_landing], insecure: true).run
      expect(report).not_to be_passed
      expect(report.failed.map(&:name)).to include(:create_account)
      expect(report.to_s).to include("FAIL")
    end

    it "rejects unknown case names" do
      expect { described_class.new(login_url: "http://127.0.0.1:1/").run_case(:nope) }.to raise_error(ArgumentError)
    end
  end

  describe "shared examples" do
    before(:all) { @site = TestSite.start }
    after(:all) { @site.stop }

    let(:login_url) { @site.login_url }
    let(:conformance_features) { { ask: false, sin: false } }
    let(:conformance_options) { { insecure: true } } # the spec site is plain http on loopback

    it_behaves_like "a SQRL server"
  end
end
