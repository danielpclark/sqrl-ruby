# frozen_string_literal: true

ENV["RACK_ENV"] = "test"
$LOAD_PATH.unshift File.expand_path("../../sqrl-core/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sqrl/rack"
require "rack/test"
require "rack/session"
require_relative "support/client_helpers"

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed
end
