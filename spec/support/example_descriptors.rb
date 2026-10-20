# frozen_string_literal: true

# One table describing how each example application is laid out, so the shared integration
# examples can drive every framework the same way. Adjust here when an example changes.
#
#   login_path       page carrying the SQRL login block (the bot's login URL)
#   login_page       optional proc(transport, app) -> Transport::Response fetching that page
#                    when a plain GET will not do (OmniAuth's CSRF-protected POST request
#                    phase); the integration transport runs it for GETs of +login_path+
#   browser_login    optional proc(page, app) that brings a Capybara session to the login page
#   protected_path   page answering 200 only when logged in (403 otherwise)
#   logged_in        proc(response_or_html_string) -> Boolean: the landing shows a login
#   logout           { text: button text } for the browser flow, or nil
#   cancel           true when the login block carries a cancel link back to +home_path+
#   features         conformance feature overrides (see Conformance::Runner::DEFAULT_FEATURES)
#   ready            file (relative to the example dir) that only exists once the example is built
#   ready_pattern    optional regex the +ready+ file must match
require "cgi"

module ExampleDescriptors
  Descriptor = Struct.new(:name, :login_path, :login_page, :browser_login, :protected_path, :home_path,
                          :logged_in, :logout, :cancel, :features, :ready, :ready_pattern, :anonymous_status,
                          keyword_init: true) do
    def login_url(app) = app.url(login_path)

    # HTTP status the protected page answers to a browser that has not logged in:
    # 403 for the Rack-style examples, 302 (redirect to the sign-in page) for Rails and Devise.
    def anonymous_protected_status = anonymous_status || 403
  end

  IDK_MARKER = /Hello, <code>[A-Za-z0-9_-]{43}<\/code>|id="identity"|Logged in as/

  ALL = {
    "rack-app" => Descriptor.new(
      name: "rack-app", login_path: "/login", protected_path: "/protected", home_path: "/",
      logged_in: ->(body) { body.match?(IDK_MARKER) }, logout: { text: "Log out" }, cancel: true,
      features: {}, ready: "config.ru"
    ),
    "sinatra-app" => Descriptor.new(
      name: "sinatra-app", login_path: "/login", protected_path: "/protected", home_path: "/",
      logged_in: ->(body) { body.match?(IDK_MARKER) }, logout: { text: "Log out" }, cancel: true,
      features: {}, ready: "config.ru"
    ),
    "omniauth-app" => Descriptor.new(
      name: "omniauth-app", login_path: "/auth/sqrl",
      # OmniAuth 2's request phase is a CSRF-protected POST: fetch the home page for the
      # session cookie and the hidden token, then POST them to /auth/sqrl. The integration
      # transport performs this whenever the bot fetches +login_path+.
      login_page: lambda { |transport, app|
        home = transport.get(app.url("/"))
        token = home.body[/name="authenticity_token" value="([^"]+)"/, 1]
        raise "no authenticity_token on #{app.url('/')}" unless token

        transport.post_form(app.url("/auth/sqrl"), "authenticity_token=#{CGI.escape(token)}")
      },
      browser_login: ->(page, app) { page.visit(app.url("/")); page.click_button("Sign in with SQRL") },
      protected_path: "/protected", home_path: "/",
      logged_in: ->(body) { body.match?(/Logged in as|id="uid"/) }, logout: { text: "Log out" }, cancel: false,
      features: {}, ready: "config.ru"
    ),
    "rails-auth-app" => Descriptor.new(
      name: "rails-auth-app", login_path: "/session/new", protected_path: "/protected", home_path: "/",
      logged_in: ->(body) { body.match?(/<p id="status">Signed in as|id="protected"/) }, logout: { text: "Sign out" }, cancel: false,
      features: {}, ready: "config/initializers/sqrl.rb", anonymous_status: 302
    ),
    "devise-app" => Descriptor.new(
      name: "devise-app", login_path: "/users/sign_in", protected_path: "/protected", home_path: "/",
      logged_in: ->(body) { body.match?(/<p id="status">Signed in as|id="protected"/) }, logout: { text: "Log out" },
      cancel: false, features: {}, ready: "app/models/user.rb", ready_pattern: /sqrl_authenticatable/,
      anonymous_status: 302
    )
  }.freeze

  def self.[](name) = ALL.fetch(name)
end
