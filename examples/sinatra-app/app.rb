# frozen_string_literal: true

# A Sinatra site with SQRL login through the Sinatra::SQRL extension.
#
# SQRL_HOST sets the public host placed in sqrl:// URLs; SQRL_ASK=1 poses an ask= question
# (Allow / Deny) on every login; SQRL_SIN=1 sends a sin= secret-index challenge.
require "bundler/setup"
require "securerandom"
require "sinatra/base"
require "sinatra/sqrl"

class SinatraApp < Sinatra::Base
  STORES = SQRL::Server::Memory.stores

  set :root, __dir__
  set :host_authorization, { permitted_hosts: [] }
  set :sessions, key: "sinatra-app.session", same_site: :lax
  set :session_secret, ENV.fetch("SESSION_SECRET") { SecureRandom.hex(64) }

  register Sinatra::SQRL
  set :sqrl,
      stores: STORES,
      host: ENV["SQRL_HOST"],
      after_login: "/protected",
      on_unknown_identity: (ENV["SQRL_UNKNOWN_IDENTITY"] || :create).to_sym,
      require_ip_match: ENV["SQRL_IGNORE_IP"].nil?,
      ask: (SQRL::Ask.new(message: "Allow this login from the Sinatra demo?", buttons: [{ label: "Allow" }, { label: "Deny" }], accept: [1]) if ENV["SQRL_ASK"]),
      sin: (ENV["SQRL_SIN"] ? "0" : nil)

  sqrl_on_login do |identity, env|
    env["rack.session"]["login_count"] = env["rack.session"].fetch("login_count", 0) + 1
    env["rack.logger"]&.info("SQRL login: #{identity.idk_b64}")
  end

  get "/" do
    erb :index
  end

  get "/login" do
    erb :login
  end

  get "/protected" do
    halt 403, erb(:forbidden) unless sqrl_authenticated?
    erb :protected
  end

  post "/logout" do
    sqrl_logout!
    redirect "/", 303
  end
end
