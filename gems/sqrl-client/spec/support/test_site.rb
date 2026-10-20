# frozen_string_literal: true

require "json"
require "rack"
require "puma"
require "puma/server"
require "sqrl"

# A tiny SQRL-enabled website built directly on SQRL::Server::Handler, served by Puma on
# a random loopback port. Its routes mirror the contract the framework integrations
# implement (login page with the sqrl.js markup, SQRL endpoint, cookie-bound status poll,
# one-time CPS callback) so the client and conformance specs exercise the real thing.
class TestSite
  attr_reader :handler, :stores, :port, :host, :base_url, :config

  def self.start(**config)
    new(**config).tap(&:start)
  end

  def initialize(host: "127.0.0.1", **config)
    @host = host
    @extra_config = config
    @stores = SQRL::Server::Memory.stores
    @on_authenticated = []
  end

  def start
    @server = Puma::Server.new(method(:call), nil, min_threads: 0, max_threads: 4, log_writer: Puma::LogWriter.null)
    @server.add_tcp_listener(@host, 0)
    @port = @server.connected_ports.first
    @base_url = "http://#{@host}:#{@port}"
    # The spec site is plain http on loopback, so it runs in the insecure_http testing mode;
    # agents and transports in the specs opt in with insecure: true / allow_http: :loopback.
    @config = SQRL::Server::Config.new(host: "#{@host}:#{@port}", insecure_http: true,
                                       on_authenticated: ->(*a) { @on_authenticated.each { |cb| cb.call(*a) } },
                                       **@extra_config)
    @handler = SQRL::Server::Handler.new(config: @config, stores: @stores)
    @thread = @server.run
    self
  end

  def stop
    @server&.stop(true)
    @thread&.join(5)
  end

  def on_authenticated(&block)
    @on_authenticated << block
  end

  def login_url = "#{@base_url}/login"
  def identity_count = @stores.identities.count

  def call(env)
    req = Rack::Request.new(env)
    case [req.request_method, req.path]
    when ["GET", "/login"] then login_page(req)
    when ["POST", @config.path] then cli(req)
    when ["GET", "/sqrl/status"] then status(req)
    when ["GET", @config.callback_path] then callback(req)
    when ["GET", "/welcome"] then welcome(req)
    when ["GET", "/logout"] then redirect("/login", "user" => nil)
    when ["GET", "/cancelled"] then html("<h1>Cancelled</h1>")
    when ["GET", "/"] then html("<h1>Test site</h1><a href=\"/login\">Log in</a>")
    else [404, { "content-type" => "text/plain" }, ["not found"]]
    end
  end

  private

  def login_page(req)
    login = @handler.new_login_url(ip: req.ip, cancel_url: "/cancelled", return_to: "/welcome")
    body = <<~HTML
      <!doctype html><html><head><meta charset="utf-8"><title>Log in</title></head><body>
      <h1>Log in</h1>
      <div data-sqrl-login data-sqrl-url="#{escape(login.url)}" data-sqrl-status="/sqrl/status" data-sqrl-poll="500">
        <a data-sqrl-link href="#{escape(login.url)}">Sign in with SQRL</a>
        <p data-sqrl-message>Waiting…</p>
      </div>
      <p>Debug: <code>#{escape(login.url)}</code></p>
      </body></html>
    HTML
    html(body, "pl" => login.pending_login_id)
  end

  def cli(req)
    body = req.body.read
    result = @handler.handle(nut: req.GET["nut"].to_s, body: body, ip: req.ip)
    [200, { "content-type" => "text/plain", "cache-control" => "no-store" }, [result.body]]
  end

  def status(req)
    st = @handler.status(req.cookies["pl"])
    headers = { "content-type" => "application/json", "cache-control" => "no-store" }
    payload = st.merge(next: nil)
    if st[:authenticated]
      payload[:next] = "/welcome"
      Rack::Utils.set_cookie_header!(headers, "user", value: st[:idk], path: "/", http_only: true)
    end
    [200, headers, [JSON.generate(payload)]]
  end

  def callback(req)
    login = @handler.claim_cps(req.GET["t"])
    unless login&.authenticated?
      return [403, { "content-type" => "text/html" },
              ["<h1>Invalid or expired login token</h1>"]]
    end

    redirect(login.return_to || "/welcome", "user" => SQRL::Util.b64u_encode(login.authenticated_idk))
  end

  def welcome(req)
    user = req.cookies["user"]
    return [403, { "content-type" => "text/html" }, ["<h1>Not logged in</h1>"]] if user.nil? || user.empty?

    html("<h1>Welcome</h1><p id=\"idk\">#{escape(user)}</p><a href=\"/logout\">Log out</a>")
  end

  def html(body, cookies = {})
    headers = { "content-type" => "text/html; charset=utf-8", "cache-control" => "no-store" }
    cookies.each { |k, v| Rack::Utils.set_cookie_header!(headers, k, value: v.to_s, path: "/", http_only: true) }
    [200, headers, [body]]
  end

  def redirect(location, cookies = {})
    headers = { "location" => location, "content-type" => "text/html" }
    cookies.each do |k, v|
      if v.nil?
        Rack::Utils.delete_cookie_header!(headers, k, path: "/")
      else
        Rack::Utils.set_cookie_header!(headers, k, value: v.to_s, path: "/", http_only: true)
      end
    end
    [303, headers, ["redirecting"]]
  end

  def escape(s) = Rack::Utils.escape_html(s)
end
