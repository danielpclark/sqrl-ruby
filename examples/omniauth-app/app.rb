# frozen_string_literal: true

# A Sinatra site that signs users in with OmniAuth's :sqrl provider.
require "bundler/setup"
require "securerandom"
require "sinatra/base"
require "omniauth"
require "omniauth-sqrl"

class OmniauthApp < Sinatra::Base
  STORES = SQRL::Server::Memory.stores

  set :root, __dir__
  set :host_authorization, { permitted_hosts: [] }
  set :sessions, key: "omniauth-app.session", same_site: :lax
  set :session_secret, ENV.fetch("SESSION_SECRET") { SecureRandom.hex(64) }

  # OmniAuth 2 only accepts POST on /auth/sqrl and checks an authenticity token on it.
  # The token comes from Rack::Protection (which Sinatra's `sessions` already enables),
  # so the login form below carries the same token OmniAuth verifies. Rails apps get the
  # same from the omniauth-rails_csrf_protection gem.
  use OmniAuth::Builder do
    provider :sqrl,
             stores: OmniauthApp::STORES,
             host: ENV["SQRL_HOST"],
             on_unknown_identity: (ENV["SQRL_UNKNOWN_IDENTITY"] || :create).to_sym,
             require_ip_match: ENV["SQRL_IGNORE_IP"].nil?,
             # SQRL_ASK=1 poses an ask= (Allow / Deny) on every login; SQRL_SIN=1 sends a sin= challenge.
             ask: (SQRL::Ask.new(message: "Allow this login from the OmniAuth demo?", buttons: [{ label: "Allow" }, { label: "Deny" }]) if ENV["SQRL_ASK"]),
             sin: (ENV["SQRL_SIN"] ? "0" : nil),
             title: "OmniAuth SQRL demo"
  end

  helpers do
    def current_uid = session["uid"]
    def authenticity_token = Rack::Protection::AuthenticityToken.token(session)
  end

  get "/" do
    erb :index
  end

  # OmniAuth hands the auth hash to the application here.
  get "/auth/sqrl/callback" do
    auth = request.env["omniauth.auth"]
    session["uid"] = auth["uid"]
    session["sqrl"] = auth["extra"]["sqrl"].to_h
    session["login_count"] = session.fetch("login_count", 0) + 1
    redirect "/protected", 303
  end

  get "/auth/failure" do
    status 403
    erb :failure
  end

  get "/protected" do
    halt 403, erb(:forbidden) unless current_uid
    erb :protected
  end

  post "/logout" do
    session.clear
    redirect "/", 303
  end
end
