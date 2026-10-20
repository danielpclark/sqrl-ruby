# frozen_string_literal: true

require_relative "conformance/report"
require_relative "conformance/site"
require_relative "conformance/runner"

module SQRL
  module Client
    # A behavioural test-suite for SQRL servers, driven through the bot client. Point it at
    # a login page and it exercises account creation, login with and without CPS, the
    # account commands, re-keying, +ask+/+sin+ (when the site uses them) and a battery of
    # negative protocol cases.
    #
    #   report = SQRL::Client::Conformance::Runner.new(login_url: "https://example.com/login").run
    #   puts report
    #   report.passed?  # => true
    #
    # In RSpec: +require "sqrl/client/conformance/rspec"+ and
    # +it_behaves_like "a SQRL server"+ with +let(:login_url)+.
    module Conformance
    end
  end
end
