# frozen_string_literal: true

require_relative "../sqrl-core/lib/sqrl/version" unless defined?(SQRL::VERSION)

Gem::Specification.new do |spec|
  spec.name = "sqrl-rails"
  spec.version = SQRL::VERSION
  spec.authors = ["Daniel P. Clark"]
  spec.email = ["6ftdan@gmail.com"]
  spec.summary = "SQRL login for Rails: engine, generator, ActiveRecord stores and Rails 8 Authentication support"
  spec.homepage = "https://github.com/danielpclark/ruby_sqrl"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "#{spec.homepage}/tree/main/gems/sqrl-rails"
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/gems/sqrl-rails/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "#{spec.homepage}/blob/main/gems/sqrl-rails/README.md"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.files = Dir["lib/**/*", "app/**/*", "config/**/*", "db/**/*", "LICENSE", "README.md", "CHANGELOG.md"]
  spec.require_paths = ["lib"]
  spec.add_dependency "rails", ">= 7.1", "< 9"
  spec.add_dependency "sqrl-core", "~> #{SQRL::VERSION}"
  spec.add_dependency "sqrl-rack", "~> #{SQRL::VERSION}"
end
