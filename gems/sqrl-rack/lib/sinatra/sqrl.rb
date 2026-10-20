# frozen_string_literal: true

require "sinatra/base"
require "sqrl/rack"

# Sinatra namespace, reopened to add the SQRL extension.
module Sinatra
  # SQRL login for Sinatra.
  #
  #   require "sinatra/sqrl"
  #
  #   class App < Sinatra::Base
  #     enable :sessions
  #     register Sinatra::SQRL
  #     set :sqrl, host: "example.com", stores: SQRL::Server::Memory.stores
  #
  #     sqrl_on_login { |identity, env| env["rack.session"]["user"] = identity.idk_b64 }
  #
  #     get("/login") { sqrl_login_block }
  #     get("/") { sqrl_authenticated? ? "hello #{current_sqrl_identity.idk_b64}" : redirect("/login") }
  #   end
  #
  # Registering adds {SQRL::Rack::Middleware} to the app. Sinatra builds its own session
  # and +Rack::Protection+ middleware before any +use+d middleware, so the session is
  # available and the SQRL endpoint is reached before the application; with sessions on,
  # +Rack::Protection+'s defaults let the SQRL client's token-less POST through (it has
  # no cross-site referrer). Options given with +set :sqrl+ are read when the app is
  # built, so their order relative to +register+ does not matter.
  module SQRL
    # Instance helpers.
    module Helpers
      # @return [SQRL::Rack::Facade]
      def sqrl
        env["sqrl.server"] or raise ::SQRL::Rack::Error, "SQRL middleware did not run for this request"
      end

      # @return [String] a fresh +sqrl://+ login URL for this request (see {SQRL::Rack::Facade#login_url})
      def sqrl_login_url(**options) = sqrl.login_url(**options).url
      # @return [String] the login URL as an SVG QR code
      def sqrl_qr_svg(**options) = sqrl.qr_svg(**options)
      # @return [String] a +<script>+ tag loading +sqrl.js+
      def sqrl_script_tag = sqrl.script_tag
      # @return [String] the complete login block markup (see {SQRL::Rack::LoginBlock.render})
      def sqrl_login_block(**options) = sqrl.login_block(**options)
      def sqrl_authenticated? = sqrl.authenticated?
      # @return [SQRL::Server::Identity, nil] the identity logged in through SQRL in this session
      def current_sqrl_identity = sqrl.identity
      # Forget the SQRL identity held in the session.
      # @return [void]
      def sqrl_logout! = sqrl.logout!
    end

    # Register a block called after every successful SQRL login with
    # +(identity, env, pending_login)+.
    def sqrl_on_login(&block)
      set :sqrl_login_hooks, sqrl_login_hooks + [block]
    end

    # Sinatra extension hook: installs the middleware lazily and the helpers.
    # @param app [Class] the Sinatra application
    def self.registered(app)
      app.helpers Helpers
      app.set :sqrl, {} unless app.respond_to?(:sqrl)
      app.set :sqrl_login_hooks, []
      app.use ::SQRL::Rack::Middleware, -> { middleware_options(app) }
    end

    # The middleware options derived from +set :sqrl+.
    # @api private
    def self.middleware_options(app)
      hooks = app.sqrl_login_hooks
      opts = (app.sqrl || {}).transform_keys(&:to_sym)
      return opts if hooks.empty?

      user_hook = opts[:on_login]
      opts[:session_identity] = true unless opts.key?(:session_identity)
      opts[:on_login] = lambda do |env, identity, pending_login|
        user_hook&.call(env, identity, pending_login)
        hooks.each { |h| h.call(identity, env, pending_login) }
      end
      opts
    end
  end

  register SQRL
end
