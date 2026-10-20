# frozen_string_literal: true

require_relative "lib/sqrl/version"

Gem::Specification.new do |spec|
  spec.name = "sqrl-core"
  spec.version = SQRL::VERSION
  spec.authors = ["Daniel P. Clark"]
  spec.email = ["6ftdan@gmail.com"]
  spec.summary = "SQRL (Secure Quick Reliable Login) protocol, cryptography and identity storage in pure Ruby"
  spec.description = "A complete implementation of Steve Gibson's SQRL authentication protocol: " \
                     "EnScrypt, EnHash, the identity lock, S4 identity storage, the textual identity " \
                     "format, the client transaction state machine and a server-side protocol handler."
  spec.homepage = "https://github.com/danielpclark/sqrl-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "#{spec.homepage}/tree/main/gems/sqrl-core"
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/gems/sqrl-core/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "#{spec.homepage}/blob/main/gems/sqrl-core/README.md"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.files = Dir["lib/**/*.rb", "LICENSE", "README.md", "CHANGELOG.md"]
  spec.require_paths = ["lib"]
end
