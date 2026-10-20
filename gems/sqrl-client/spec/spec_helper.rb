# frozen_string_literal: true

require "bundler/setup"
$LOAD_PATH.unshift File.expand_path("../../sqrl-core/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sqrl/client"
require_relative "support/test_site"

module SiteHelpers
  # One shared site per example group that asks for it; fresh stores per example.
  def start_site(**config)
    site = TestSite.start(**config)
    @sites ||= []
    @sites << site
    site
  end

  def stop_sites
    @sites&.each(&:stop)
    @sites = nil
  end

  def ephemeral(seed = nil) = SQRL::Client::Identity.ephemeral(seed)

  def new_agent(identity = ephemeral, **opts)
    SQRL::Client::Agent.new(identity: identity, insecure: true, **opts)
  end
end

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  config.include SiteHelpers
  config.after(:each) { stop_sites }
  Kernel.srand config.seed
end
