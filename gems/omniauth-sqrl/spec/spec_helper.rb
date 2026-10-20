# frozen_string_literal: true

ENV["RACK_ENV"] = "test"
$LOAD_PATH.unshift File.expand_path("../../sqrl-core/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../sqrl-rack/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "omniauth-sqrl"
require "rack/test"
require "rack/session"
require "json"
require_relative "support/client_helpers"

OmniAuth.config.logger = Logger.new(File::NULL)
# The request phase is exercised directly with POSTs that carry no authenticity token.
OmniAuth.config.request_validation_phase = nil

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed
  config.after { OmniAuth.config.test_mode = false }
end
