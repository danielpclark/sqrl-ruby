# frozen_string_literal: true

# A Roda application with SQRL login through the `sqrl` plugin shipped in sqrl-rack.
#
#   bundle exec rackup -p 9292
#
# SQRL_HOST sets the public host placed in sqrl:// URLs (defaults to the request host);
# SQRL_ASK=1 poses a question on login, SQRL_SIN=1 requests an indexed secret, like the
# other examples. The in-memory stores reset when the process restarts; a multi-process
# deployment would use SQRL::Server::Redis.stores or a database-backed set.

require "bundler/setup"
require "securerandom"
require "roda"
require "rack/session"
require "roda/plugins/sqrl"

class RodaApp < Roda
  STORES = SQRL::Server::Memory.stores

  use Rack::Session::Cookie,
      key: "roda-app.session",
      secret: ENV.fetch("SESSION_SECRET") { SecureRandom.hex(64) },
      same_site: :lax,
      httponly: true

  plugin :render, engine: "erb", views: File.join(__dir__, "views"), layout: "layout"
  plugin :sqrl,
         stores: STORES,
         host: ENV["SQRL_HOST"],
         after_login: "/protected",
         on_unknown_identity: (ENV["SQRL_UNKNOWN_IDENTITY"] || :create).to_sym,
         require_ip_match: ENV["SQRL_IGNORE_IP"].nil?,
         ask: (ENV["SQRL_ASK"] ? SQRL::Ask.new(message: "Allow this login?", buttons: [{ label: "Allow" }, { label: "Deny" }]) : nil),
         sin: (ENV["SQRL_SIN"] ? "0" : nil)

  route do |r|
    r.root do
      view("index")
    end

    r.get "login" do
      view("login", locals: { return_to: r.params["return_to"] })
    end

    r.get "protected" do
      unless sqrl_authenticated?
        response.status = 403
        next view("forbidden")
      end
      view("protected")
    end

    r.post "logout" do
      sqrl_logout!
      r.redirect "/", 303
    end
  end
end
