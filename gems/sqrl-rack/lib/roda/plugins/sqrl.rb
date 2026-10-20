# frozen_string_literal: true

require "roda"
require "sqrl/rack"

# Roda namespace, reopened to add the +:sqrl+ plugin.
class Roda
  # Roda's plugin namespace.
  module RodaPlugins
    # SQRL login for Roda.
    #
    #   require "roda"
    #   require "roda/plugins/sqrl"   # or just `plugin :sqrl` with sqrl-rack on the load path
    #
    #   class App < Roda
    #     use Rack::Session::Cookie, secret: ENV.fetch("SESSION_SECRET"), same_site: :lax
    #     plugin :sqrl, host: "example.com", stores: SQRL::Server::Memory.stores
    #
    #     sqrl_on_login { |identity, env| env["rack.session"]["user"] = identity.idk_b64 }
    #
    #     route do |r|
    #       r.get("login") { sqrl_login_block }
    #       r.root { sqrl_authenticated? ? "hello #{current_sqrl_identity.idk_b64}" : r.redirect("/login") }
    #     end
    #   end
    #
    # The plugin adds {SQRL::Rack::Middleware} to the application's middleware stack with
    # every option given to +plugin :sqrl+ (see {SQRL::Rack::Middleware} and
    # {SQRL::Server::Config}). Because the middleware runs *before* the Roda routing tree,
    # the session it binds logins to must come from a Rack session middleware
    # (+Rack::Session::Cookie+, +Rack::Session::Pool+, ...) added with +use+ before
    # +plugin :sqrl+. Roda's own +sessions+ plugin keeps the session inside the routing
    # tree, where the middleware cannot see it, and is therefore not supported; the
    # middleware raises a clear error when no +rack.session+ is present.
    module SQRL
      # Accepts every option of SQRL::Rack::Middleware.
      def self.configure(app, opts = {})
        app.opts[:sqrl] = (app.opts[:sqrl] || {}).merge(opts.transform_keys(&:to_sym))
        app.opts[:sqrl_login_hooks] ||= []
        return if app.opts[:sqrl_middleware_installed]

        app.opts[:sqrl_middleware_installed] = true
        app.use ::SQRL::Rack::Middleware, -> { SQRL.middleware_options(app) }
      end

      # Merge the user hooks into the middleware's +on_login+ (same shape as the Sinatra
      # extension).
      def self.middleware_options(app)
        hooks = app.opts[:sqrl_login_hooks] || []
        opts = (app.opts[:sqrl] || {}).dup
        return opts if hooks.empty?

        user_hook = opts[:on_login]
        opts[:session_identity] = true unless opts.key?(:session_identity)
        opts[:on_login] = lambda do |env, identity, pending_login|
          user_hook&.call(env, identity, pending_login)
          hooks.each { |h| h.call(identity, env, pending_login) }
        end
        opts
      end

      # Class-level API: +plugin :sqrl+ options and the +sqrl_on_login+ hook.
      module ClassMethods
        # Register a block called after every successful SQRL login with
        # +(identity, env, pending_login)+.
        def sqrl_on_login(&block)
          opts[:sqrl_login_hooks] = (opts[:sqrl_login_hooks] || []) + [block]
        end

        # The options the middleware was installed with.
        def sqrl_options = opts[:sqrl] || {}
      end

      # Helpers available inside the routing block.
      module InstanceMethods
        # @return [SQRL::Rack::Facade]
        def sqrl
          env["sqrl.server"] or raise ::SQRL::Rack::Error, "SQRL middleware did not run for this request"
        end

        # @return [String] a fresh +sqrl://+ login URL for this request
        def sqrl_login_url(**options) = sqrl.login_url(**options).url
        # @return [String] the login URL as an SVG QR code
        def sqrl_qr_svg(**options) = sqrl.qr_svg(**options)
        # @return [String] a +<script>+ tag loading +sqrl.js+
        def sqrl_script_tag = sqrl.script_tag
        # @return [String] the complete login block markup
        def sqrl_login_block(**options) = sqrl.login_block(**options)
        def sqrl_authenticated? = sqrl.authenticated?
        # @return [SQRL::Server::Identity, nil] the identity logged in through SQRL in this session
        def current_sqrl_identity = sqrl.identity
        # Forget the SQRL identity held in the session.
        # @return [void]
        def sqrl_logout! = sqrl.logout!
      end

      # The same helpers on the request object, for people who route everything through +r+.
      module RequestMethods
        # @return [SQRL::Rack::Facade] the request-scoped facade
        def sqrl = scope.sqrl
        def sqrl_authenticated? = scope.sqrl_authenticated?
        # @return [SQRL::Server::Identity, nil] the identity logged in through SQRL in this session
        def current_sqrl_identity = scope.current_sqrl_identity
      end
    end

    register_plugin(:sqrl, SQRL)
  end
end
