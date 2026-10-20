# frozen_string_literal: true

require_relative "../sqrl-core/lib/sqrl/version" unless defined?(SQRL::VERSION)

Gem::Specification.new do |spec|
  spec.name = "omniauth-sqrl"
  spec.version = SQRL::VERSION
  spec.authors = ["Daniel P. Clark"]
  spec.email = ["6ftdan@gmail.com"]
  spec.summary = "OmniAuth strategy for SQRL login"
  spec.homepage = "https://github.com/danielpclark/ruby_sqrl"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.files = Dir["lib/**/*", "LICENSE", "README.md", "CHANGELOG.md"]
  spec.require_paths = ["lib"]
  spec.add_dependency "omniauth", "~> 2.0"
  spec.add_dependency "sqrl-core", SQRL::VERSION
  spec.add_dependency "sqrl-rack", SQRL::VERSION
end
