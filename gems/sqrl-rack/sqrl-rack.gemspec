# frozen_string_literal: true

require_relative "../sqrl-core/lib/sqrl/version" unless defined?(SQRL::VERSION)

Gem::Specification.new do |spec|
  spec.name = "sqrl-rack"
  spec.version = SQRL::VERSION
  spec.authors = ["Daniel P. Clark"]
  spec.email = ["6ftdan@gmail.com"]
  spec.summary = "SQRL login for Rack applications and Sinatra"
  spec.description = "Rack middleware serving the SQRL endpoint, status poll and CPS callback, a Sinatra " \
                     "extension with view helpers, the browser-side script and QR code rendering."
  spec.homepage = "https://github.com/danielpclark/ruby_sqrl"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "#{spec.homepage}/tree/main/gems/sqrl-rack"
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/gems/sqrl-rack/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "#{spec.homepage}/blob/main/gems/sqrl-rack/README.md"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.files = Dir["lib/**/*", "assets/**/*", "LICENSE", "README.md", "CHANGELOG.md"]
  spec.require_paths = ["lib"]
  spec.add_dependency "rack", ">= 2.2", "< 4"
  spec.add_dependency "rqrcode", "~> 3.0"
  spec.add_dependency "sqrl-core", "~> #{SQRL::VERSION}"
end
