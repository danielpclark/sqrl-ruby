# frozen_string_literal: true

require_relative "../sqrl-core/lib/sqrl/version" unless defined?(SQRL::VERSION)

Gem::Specification.new do |spec|
  spec.name = "sqrl-client"
  spec.version = SQRL::VERSION
  spec.authors = ["Daniel P. Clark"]
  spec.email = ["6ftdan@gmail.com"]
  spec.summary = "Bot-capable SQRL client: log in to SQRL-enabled websites from scripts and test suites"
  spec.description = "Identity management, the full SQRL command set, CPS handoff, login-page discovery, " \
                     "a Capybara helper, a CLI and a server conformance suite."
  spec.homepage = "https://github.com/danielpclark/sqrl-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "#{spec.homepage}/tree/main/gems/sqrl-client"
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/gems/sqrl-client/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "#{spec.homepage}/blob/main/gems/sqrl-client/README.md"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.files = Dir["lib/**/*.rb", "exe/*", "LICENSE", "README.md", "CHANGELOG.md"]
  spec.bindir = "exe"
  spec.executables = ["sqrl-client"]
  spec.require_paths = ["lib"]
  spec.add_dependency "http-cookie", "~> 1.0"
  spec.add_dependency "sqrl-core", "~> #{SQRL::VERSION}"
end
