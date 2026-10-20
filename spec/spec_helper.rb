# frozen_string_literal: true

# Root spec helper for the repository-level suites (integration and interop). The gems'
# own suites live under gems/<name>/spec with their own helpers.
require "bundler/setup"
$LOAD_PATH.unshift File.expand_path("../gems/sqrl-core/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../gems/sqrl-client/lib", __dir__)

Dir[File.join(__dir__, "support", "*.rb")].sort.each { |f| require f }

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :defined
end
