# frozen_string_literal: true

require_relative "../integration_helpers"

# The behaviour of an example application booted with SQRL_ASK=1 and SQRL_SIN=1: the site
# poses an ask= question on every login and sends a sin= challenge. Include
# "live example app" with ExampleDescriptors::Descriptor::ASK_SIN_ENV first.
RSpec.shared_examples "a live SQRL example app with ask and sin" do
  # Only the cases that exercise ask/sin plus the two happy paths that prove the site still
  # logs people in with both features on.
  ASK_SIN_CASES = %i[create_account login_existing ask_and_button sin_and_ins].freeze

  describe "conformance suite (ask and sin on)" do
    let(:runner) do
      SQRL::Client::Conformance::Runner.new(login_url: login_url, features: descriptor.features.merge(ask: true, sin: true),
                                            site: site, transport_factory: -> { new_transport }, only: ASK_SIN_CASES)
    end

    ASK_SIN_CASES.each do |name|
      it "#{SQRL::Client::Conformance::Runner::CASES.fetch(name).first}: #{name.to_s.tr("_", " ")}" do
        kase = runner.run_case(name)
        skip(kase.message) if kase.skipped?
        raise kase.error || RSpec::Expectations::ExpectationNotMetError.new(kase.message) if kase.failed?
      end
    end
  end

  describe "bot client flows" do
    it "poses the ask to a known identity, logs in when it is allowed, and sends ins= for the sin" do
      id = ephemeral
      first = login_via_site(new_agent(id, ask_handler: ->(_ask) { 1 }))
      expect(first).to be_created
      expect_logged_in(first)

      asked = nil
      second = login_via_site(new_agent(id, ask_handler: lambda { |ask|
        asked = ask
        1
      }))
      expect(asked).not_to be_nil, "the site posed no ask= to the returning identity"
      expect(asked.message).to match(/Allow this login/)
      expect(asked.buttons.map(&:label)).to eq(%w[Allow Deny])
      expect(second.ask).to eq(asked)
      expect(second.button).to eq(1)
      expect_logged_in(second)

      ident = second.transcript.last
      expect(ident[:client_text]).to include("btn=1", "ins=")
      expect(second.transcript.any? { |t| t[:response].key?("sin") }).to be(true)
    end

    it "raises AskRequired when no handler answers the question" do
      id = ephemeral
      login_via_site(new_agent(id, ask_handler: ->(_ask) { 1 }))
      expect { login_via_site(new_agent(id)) }.to raise_error(SQRL::Client::AskRequired)
    end

    it "refuses the login when the ask is answered with Deny" do
      id = ephemeral
      login_via_site(new_agent(id, ask_handler: ->(_ask) { 1 }))
      expect { login_via_site(new_agent(id, ask_handler: ->(_ask) { 2 })) }.to raise_error(SQRL::Client::LoginFailed)
    end
  end
end
