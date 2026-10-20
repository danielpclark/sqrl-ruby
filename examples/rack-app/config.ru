# frozen_string_literal: true

# A bare Rack application with SQRL login: no framework, just a session middleware,
# SQRL::Rack::Middleware and a few routes.
#
#   bundle exec rackup -p 9292
#
# SQRL_HOST sets the public host placed in sqrl:// URLs (defaults to the request host).
# SQRL_ASK=1 poses an ask= question (Allow / Deny) on every login; SQRL_SIN=1 sends a
# sin= secret-index challenge. The in-memory stores reset when the process restarts; a real
# site uses persistent ones.

require "bundler/setup"
require "securerandom"
require "rack"
require "rack/session"
require "sqrl/rack"

STORES = SQRL::Server::Memory.stores unless defined?(STORES)

use Rack::Session::Cookie,
    key: "rack-app.session",
    secret: ENV.fetch("SESSION_SECRET") { SecureRandom.hex(64) },
    same_site: :lax,
    httponly: true

use SQRL::Rack::Middleware,
    stores: STORES,
    host: ENV["SQRL_HOST"],
    # SQRL URLs are sqrl:// and always mean HTTPS. Only for plain-http testing on a loopback
    # host with the browser extension's local flow (non-standard qrl:// URLs):
    insecure_http: ENV["SQRL_INSECURE_HTTP"] == "1",
    after_login: "/protected",
    on_unknown_identity: (ENV["SQRL_UNKNOWN_IDENTITY"] || :create).to_sym,
    require_ip_match: ENV["SQRL_IGNORE_IP"].nil?,
    ask: (SQRL::Ask.new(message: "Allow this login from the Rack demo?", buttons: [{ label: "Allow" }, { label: "Deny" }], accept: [1]) if ENV["SQRL_ASK"]),
    sin: (ENV["SQRL_SIN"] ? "0" : nil)

module RackApp
  module_function

  def html(status, title, body)
    page = <<~HTML
      <!doctype html>
      <html lang="en"><head><meta charset="utf-8"><title>#{title}</title>
      <style>body{font-family:system-ui,sans-serif;max-width:40em;margin:3em auto;line-height:1.5}
      .sqrl-login__link{display:inline-block;padding:.6em 1.2em;background:#007cc3;color:#fff;border-radius:.4em;text-decoration:none}
      .sqrl-login__qr svg{display:block;margin:1em 0}</style></head>
      <body><h1>#{title}</h1>#{body}</body></html>
    HTML
    [status, { "content-type" => "text/html; charset=utf-8", "cache-control" => "no-store" }, [page]]
  end

  def call(env)
    request = Rack::Request.new(env)
    sqrl = env["sqrl.server"]
    case [request.request_method, request.path_info]
    when ["GET", "/"]
      if sqrl.authenticated?
        html(200, "Rack SQRL demo", "<p id=\"state\">Logged in as <code>#{sqrl.idk_b64}</code>.</p>" \
                                    '<p><a href="/protected">Protected page</a></p>' \
                                    '<form method="post" action="/logout"><button>Log out</button></form>')
      else
        html(200, "Rack SQRL demo", '<p id="state">Not logged in.</p><p><a href="/login">Sign in with SQRL</a></p>')
      end
    when ["GET", "/login"]
      html(200, "Sign in", sqrl.login_block(cancel_url: "/", return_to: request.GET["return_to"]))
    when ["GET", "/protected"]
      if sqrl.authenticated?
        html(200, "Protected", "<p id=\"identity\">Hello, <code>#{sqrl.idk_b64}</code>.</p><p><a href=\"/\">Home</a></p>")
      else
        html(403, "Forbidden", '<p>You need to <a href="/login?return_to=/protected">sign in</a> first.</p>')
      end
    when ["POST", "/logout"]
      sqrl.logout!
      [303, { "location" => "/" }, []]
    else
      html(404, "Not found", "<p>No such page.</p>")
    end
  end
end

run RackApp
