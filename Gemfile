# frozen_string_literal: true

source "https://rubygems.org"

# The gems in this monorepo, loaded from their local paths.
gem "sqrl-core", path: "gems/sqrl-core"
gem "sqrl-rack", path: "gems/sqrl-rack"
gem "omniauth-sqrl", path: "gems/omniauth-sqrl"
gem "sqrl-rails", path: "gems/sqrl-rails"
gem "devise-sqrl", path: "gems/devise-sqrl"
gem "sqrl-client", path: "gems/sqrl-client"

group :development, :test do
  gem "rake", "~> 13.0"
  gem "rspec", "~> 3.13"
  gem "rack", ">= 2.2"
  gem "rackup"
  gem "rack-test"
  gem "rack-session"
  gem "puma"
  gem "sinatra", ">= 3.0"
  gem "omniauth", "~> 2.1"
  gem "omniauth-rails_csrf_protection"
  gem "rails", ">= 7.1"
  gem "devise", ">= 4.9"
  gem "sqlite3", ">= 2.0"
  gem "propshaft"
  gem "rqrcode", "~> 3.0"
  gem "http-cookie", "~> 1.0"
  gem "nokogiri"
  gem "capybara"
  gem "cuprite"
  gem "webrick"
  gem "roda", ">= 3.0"      # Roda plugin specs
  gem "redis", ">= 5.0"     # Redis store specs (skip without a server)
  gem "simplecov", require: false
end
