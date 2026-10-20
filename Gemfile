# frozen_string_literal: true

source "https://rubygems.org"

# The gems in this monorepo, loaded from their local paths.
gem "devise-sqrl", path: "gems/devise-sqrl"
gem "omniauth-sqrl", path: "gems/omniauth-sqrl"
gem "sqrl-client", path: "gems/sqrl-client"
gem "sqrl-core", path: "gems/sqrl-core"
gem "sqrl-rack", path: "gems/sqrl-rack"
gem "sqrl-rails", path: "gems/sqrl-rails"

group :development, :test do
  gem "capybara"
  gem "cuprite"
  gem "devise", ">= 4.9"
  gem "http-cookie", "~> 1.0"
  gem "nokogiri"
  gem "omniauth", "~> 2.1"
  gem "omniauth-rails_csrf_protection"
  gem "propshaft"
  gem "puma"
  gem "rack", ">= 2.2"
  gem "rack-session"
  gem "rack-test"
  gem "rackup"
  gem "rails", ">= 7.1"
  gem "rake", "~> 13.0"
  gem "redis", ">= 5.0"     # Redis store specs (skip without a server)
  gem "roda", ">= 3.0"      # Roda plugin specs
  gem "rqrcode", "~> 3.0"
  gem "rspec", "~> 3.13"
  gem "simplecov", require: false
  gem "sinatra", ">= 3.0"
  gem "sqlite3", ">= 2.0"
  gem "webrick"
end
