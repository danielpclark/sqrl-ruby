# frozen_string_literal: true

require "sqrl/client"
require "sqrl/client/conformance"

# RSpec shared examples running the conformance suite case by case.
#
#   require "sqrl/client/conformance/rspec"
#
#   RSpec.describe "my SQRL site" do
#     let(:login_url) { "http://127.0.0.1:9292/login" }
#     let(:conformance_features) { { ask: false } }           # optional
#     let(:conformance_options) { { success_matcher: ... } }  # optional Runner keywords
#     it_behaves_like "a SQRL server"
#   end
RSpec.shared_examples "a SQRL server" do
  let(:conformance_features) { {} } unless method_defined?(:conformance_features)
  let(:conformance_options) { {} } unless method_defined?(:conformance_options)
  let(:conformance_runner) do
    SQRL::Client::Conformance::Runner.new(login_url: login_url, features: conformance_features, **conformance_options)
  end

  SQRL::Client::Conformance::Runner::CASES.each do |name, (group, _feature)|
    it "#{group}: #{name.to_s.tr("_", " ")}" do
      kase = conformance_runner.run_case(name)
      skip(kase.message) if kase.skipped?
      raise kase.error || RSpec::Expectations::ExpectationNotMetError.new(kase.message) if kase.failed?
    end
  end
end
