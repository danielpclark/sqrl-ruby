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
    @endpoints = {}

    class << self
      # The {::SQRL::Rack::Endpoint} serving a Devise mapping for a request's host and
      # scheme. Memoized per [mapping, host, scheme]; the stores are shared with
      # sqrl-rails (+config.sqrl.stores+).
      #
      # @param mapping [Devise::Mapping]
      # @param request [ActionDispatch::Request, Rack::Request]
      # @return [::SQRL::Rack::Endpoint]
      def endpoint_for(mapping, request)
        config = ::SQRL::Rails.config
        host = config.host.presence || request.host_with_port
        scheme = config.scheme.presence || default_scheme(request, host)
        key = [mapping.name, mapping.fullpath, host, scheme]
        @mutex.synchronize { @endpoints[key] ||= build_endpoint(mapping, host, scheme) }
      end

      # Forget memoized endpoints (tests, configuration changes).
      def reset!
        @mutex.synchronize { @endpoints = {} }
        ::SQRL::Rails.reset!
      end

      # Devise-level paths of a mapping's SQRL routes.
      #
      # @return [Hash{Symbol => String}]
      def paths_for(mapping)
        base = "#{mapping.fullpath}/sqrl".squeeze("/")
        { new: base, cli: "#{base}/cli", status: "#{base}/status", callback: "#{base}/callback",
          script: "#{base}/sqrl.js" }
      end

      # The effective unknown-identity policy: Devise's +sqrl_on_unknown_identity+ when
      # set, otherwise +config.sqrl.on_unknown_identity+.
      #
      # @return [Symbol] +:create+, +:link+ or +:refuse+
      def on_unknown_identity
        (Devise.sqrl_on_unknown_identity || ::SQRL::Rails.config.on_unknown_identity || :create).to_sym
      end

      private

      def default_scheme(request, host)
        bare = host.to_s.sub(/:\d+\z/, "").downcase
        request.scheme == "http" && ::SQRL::URL.loopback?(bare) ? "qrl" : "sqrl"
      end

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
                                   script_path: paths[:script], ip: rails_config.ip || method(:client_ip))
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
end

Devise.add_module :sqrl_authenticatable,
                  strategy: true,
                  controller: :sqrl,
                  route: { sqrl: %i[new cli status callback script] },
                  model: "devise/models/sqrl_authenticatable",
                  no_input: true

require_relative "sqrl/routes"
require_relative "strategies/sqrl_authenticatable"
require_relative "sqrl/engine"
