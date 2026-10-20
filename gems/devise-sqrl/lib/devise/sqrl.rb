# frozen_string_literal: true

require "devise"
require "sqrl-rails"

module Devise
  # SQRL login for Devise.
  #
  #   # Gemfile
  #   gem "devise-sqrl"
  #
  #   class User < ApplicationRecord
  #     devise :database_authenticatable, :sqrl_authenticatable
  #   end
  #
  # `devise_for :users` then routes +/users/sqrl+ (login page), +POST /users/sqrl/cli+ (the
  # SQRL endpoint), +/users/sqrl/status+ (cookie-bound poll), +/users/sqrl/callback+
  # (login completion, through the +:sqrl_authenticatable+ Warden strategy) and
  # +/users/sqrl/sqrl.js+. Render the login block inside your sign-in page with
  # +<%= render "devise/shared/sqrl", resource_name: resource_name %>+.
  #
  # Protocol and storage settings come from +Rails.application.config.sqrl+ (the sqrl-rails
  # gem); the Devise-specific choices are the +sqrl_*+ options below, set in
  # +Devise.setup+.
  module SQRL
    VERSION = ::SQRL::VERSION

    # Raised for configuration problems.
    class Error < ::SQRL::Error; end

    @mutex = Mutex.new
    @resolver = nil

    class << self
      # The {::SQRL::Rack::Endpoint} serving a Devise mapping for a request's host and
      # scheme. Memoized per [host, scheme, mapping] in a bounded
      # {::SQRL::Rack::HostResolver} cache; the stores are shared with sqrl-rails
      # (+config.sqrl.stores+).
      #
      # @param mapping [Devise::Mapping]
      # @param request [ActionDispatch::Request, Rack::Request]
      # @return [::SQRL::Rack::Endpoint]
      # @raise [::SQRL::Rack::HostNotAllowed] when the request host may not be used
      def endpoint_for(mapping, request)
        resolver = host_resolver
        host, scheme = resolver.resolve(request)
        resolver.fetch([host, scheme, mapping.name, mapping.fullpath]) { build_endpoint(mapping, host, scheme) }
      end

      # The host resolver built from +config.sqrl+ (host, scheme, allowed_hosts,
      # host_cache_limit).
      def host_resolver
        config = ::SQRL::Rails.config
        @mutex.synchronize do
          @resolver ||= ::SQRL::Rack::HostResolver.new(host: config.host.presence, scheme: config.scheme.presence,
                                                       allowed_hosts: config.allowed_hosts,
                                                       limit: config.host_cache_limit,
                                                       logger: config.logger || ::Rails.logger)
        end
      end

      # Forget memoized endpoints (tests, configuration changes).
      def reset!
        @mutex.synchronize { @resolver = nil }
        ::SQRL::Rails.reset!
      end

      # Devise-level paths of a mapping's SQRL routes.
      #
      # @return [Hash{Symbol => String}]
      def paths_for(mapping)
        base = "#{mapping.fullpath}/sqrl".squeeze("/")
        { new: base, cli: "#{base}/cli", status: "#{base}/status", callback: "#{base}/callback",
          script: "#{base}/sqrl.js", identities: "#{base}/identities", refresh: "#{base}/refresh" }
      end

      # Whether +strategy+ (a Warden strategy instance or name) is one that a
      # +sqrlonly+ account must not sign in through.
      def blocked_strategy?(strategy)
        name = strategy.is_a?(Symbol) || strategy.is_a?(String) ? strategy.to_sym : strategy_name(strategy)
        Array(Devise.sqrl_only_blocked_strategies).map(&:to_sym).include?(name)
      end

      def strategy_name(strategy)
        return nil if strategy.nil?

        Warden::Strategies.send(:_strategies).key(strategy.class)
      end

      # The effective unknown-identity policy: Devise's +sqrl_on_unknown_identity+ when
      # set, otherwise +config.sqrl.on_unknown_identity+.
      #
      # @return [Symbol] +:create+, +:link+ or +:refuse+
      def on_unknown_identity
        (Devise.sqrl_on_unknown_identity || ::SQRL::Rails.config.on_unknown_identity || :create).to_sym
      end

      private

      def build_endpoint(mapping, host, scheme)
        rails_config = ::SQRL::Rails.config
        paths = paths_for(mapping)
        options = rails_config.server_options.merge(on_unknown_identity: on_unknown_identity)
        server_config = ::SQRL::Server::Config.new(**options, host: host, scheme: scheme,
                                                              path: paths[:cli], callback_path: paths[:callback])
        handler = ::SQRL::Server::Handler.new(config: server_config, stores: ::SQRL::Rails.stores)
        ::SQRL::Rack::Endpoint.new(handler: handler,
                                   session_key: "devise.sqrl.#{mapping.name}.pending_login",
                                   identity_key: "devise.sqrl.#{mapping.name}.identity",
                                   status_path: paths[:status], callback_path: paths[:callback],
                                   script_path: paths[:script], refresh_path: paths[:refresh],
                                   ip: rails_config.ip || method(:client_ip))
      end

      def client_ip(request)
        request.respond_to?(:remote_ip) ? request.remote_ip : request.ip
      end
    end
  end

  # --- Devise.setup options -------------------------------------------------------------

  # What to do when an unknown SQRL identity completes a login: +:create+ an account,
  # +:link+ it to the signed-in user only, or +:refuse+. +nil+ (the default) defers to
  # +Rails.application.config.sqrl.on_unknown_identity+ (+:create+).
  mattr_accessor :sqrl_on_unknown_identity
  @@sqrl_on_unknown_identity = nil

  # Callable +(identity, resource_class) -> resource+ used to build the account for a new
  # identity under +:create+. Defaults to +SQRL::Rails::UserFactory+, which fills in a
  # non-routable email and a random password so +:validatable+ passes.
  mattr_accessor :sqrl_create_resource
  @@sqrl_create_resource = nil

  # Mark SQRL logins as "remember me" (needs +:rememberable+ on the model).
  mattr_accessor :sqrl_remember_me
  @@sqrl_remember_me = false

  # Options passed to +SQRL::Rack::LoginBlock.render+ (link text, QR size, texts...).
  mattr_accessor :sqrl_login_block
  @@sqrl_login_block = {}

  # Where to send the browser after a failed SQRL login; +nil+ means the mapping's SQRL
  # login page.
  mattr_accessor :sqrl_failure_path
  @@sqrl_failure_path = nil

  # Warden strategies a +sqrlonly+ account may not sign in through. The default blocks
  # Devise's password strategy; add your own password-like strategies here. Remember-me
  # cookies and the SQRL strategy itself are never blocked.
  mattr_accessor :sqrl_only_blocked_strategies
  @@sqrl_only_blocked_strategies = [:database_authenticatable]
end

Devise.add_module :sqrl_authenticatable,
                  strategy: true,
                  controller: :sqrl,
                  route: { sqrl: %i[new cli status callback script refresh identities unlink_identity] },
                  model: "devise/models/sqrl_authenticatable",
                  no_input: true

require_relative "sqrl/routes"
require_relative "strategies/sqrl_authenticatable"
require_relative "sqrl/hooks"
require_relative "sqrl/engine"
