# frozen_string_literal: true

require_relative "../sqrl-core/lib/sqrl/version" unless defined?(SQRL::VERSION)

Gem::Specification.new do |spec|
  spec.name = "devise-sqrl"
  spec.version = SQRL::VERSION
  spec.authors = ["Daniel P. Clark"]
  spec.email = ["6ftdan@gmail.com"]
  spec.summary = "Devise module adding SQRL login (devise :sqrl_authenticatable)"
  spec.homepage = "https://github.com/danielpclark/ruby_sqrl"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/gems/devise-sqrl/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "#{spec.homepage}/blob/main/gems/devise-sqrl/README.md"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.files = Dir["lib/**/*", "app/**/*", "config/**/*", "LICENSE", "README.md", "CHANGELOG.md"]
  spec.require_paths = ["lib"]
  spec.add_dependency "devise", ">= 4.9"
  spec.add_dependency "sqrl-rails", SQRL::VERSION
end
