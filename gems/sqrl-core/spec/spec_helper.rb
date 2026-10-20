# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

# SQRL_SPEC_WITHOUT_RAW_KEYS=1 hides OpenSSL::PKey.new_raw_private_key / new_raw_public_key
# so the suite runs the DER key path that Ruby 3.1 and 3.2 (openssl gem 3.0 / 3.1) use.
if ENV["SQRL_SPEC_WITHOUT_RAW_KEYS"]
  require "openssl"
  OpenSSL::PKey.singleton_class.send(:remove_method, :new_raw_private_key)
  OpenSSL::PKey.singleton_class.send(:remove_method, :new_raw_public_key)
end

require "sqrl/core"

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed
end
