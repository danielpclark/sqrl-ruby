# frozen_string_literal: true

module SQRL
  module Rack
    # Rack middleware that mounts SQRL login in any Rack application.
    #
    #   use Rack::Session::Cookie, secret: ENV.fetch("SESSION_SECRET")
    #   use SQRL::Rack::Middleware,
    #       stores: SQRL::Server::Memory.stores,
    #       host: "example.com",
    #       on_login: ->(env, identity, pending_login) { env["rack.session"]["user_id"] = User.for_sqrl(identity).id },
    #       after_login: "/"
    #
    # It answers +POST path+ (the SQRL endpoint; never reaches the app, so no CSRF layer
    # sees it), +GET status_path+, +GET callback_path+ and +GET script_path+, and exposes
    # +env["sqrl.server"]+ (a {Facade}) to everything else.
    #
    # Options: every {Server::Config} keyword (+host+ defaults to the request host;
    # +scheme+ defaults to +sqrl+, or +qrl+ for plain-http loopback requests) plus
    # +stores:+, +status_path:+, +script_path:+, +session_key:+, +identity_key:+,
    # +ip:+ (callable resolving the client IP), +on_login:+ (callable
    # +(env, identity, pending_login)+), +after_login:+ (path, URL or callable
    # +(env, completion) -> String+; a same-site +return_to+ recorded on the pending login
    # wins), +failure_path:+ (redirect target when the callback fails; 403 when nil) and
    # +session_identity:+ (store the +idk+ in the session; defaults to true when
    # +on_login+ is nil).
    class Middleware
      DEFAULTS = {
        path: "/sqrl/cli", callback_path: "/sqrl/callback", status_path: "/sqrl/status", script_path: "/sqrl/sqrl.js",
        session_key: Endpoint::SESSION_KEY, identity_key: Endpoint::IDENTITY_KEY, after_login: "/"
      }.freeze
      ENDPOINT_KEYS = %i[status_path script_path session_key identity_key ip poll_requires_ip_match].freeze
      MIDDLEWARE_KEYS = %i[stores on_login after_login failure_path session_identity].freeze

      # @param app [#call]
      # @param options [Hash, #call] options, or a callable returning them (resolved on
      #   the first request, which lets a Sinatra app finish its +set+ calls first)
      def initialize(app, options = {})
        @app = app
        @raw_options = options
        @mutex = Mutex.new
        @endpoints = {}
      end

      def call(env)
        request = ::Rack::Request.new(env)
        endpoint = endpoint_for(request)
        path = request.path_info
        if request.post? && path == options[:path]
          endpoint.cli(request)
        elsif request.get? && path == endpoint.status_path
          endpoint.status(request)
        elsif request.get? && path == endpoint.callback_path
          complete(endpoint, request)
        elsif request.get? && path == endpoint.script_path
          endpoint.script(request)
        else
          env["sqrl.server"] = Facade.new(endpoint, request)
          @app.call(env)
        end
      end

      # Resolved options (frozen).
      def options
        @options ||= @mutex.synchronize do
          @options || begin
            raw = @raw_options.respond_to?(:call) ? @raw_options.call : @raw_options
            DEFAULTS.merge((raw || {}).transform_keys(&:to_sym)).freeze
          end
        end
      end

      # The shared stores.
      def stores
        @stores ||= options[:stores] || Server::Memory.stores
      end

      # One {Endpoint} per (host, scheme, mount prefix) combination, built lazily.
      def endpoint_for(request)
        host = options[:host] || request.host_with_port
        scheme = options[:scheme] || default_scheme(request, host)
        prefix = request.script_name.to_s
        key = [host, scheme, prefix]
        @mutex.synchronize do
          @endpoints[key] ||= build_endpoint(host, scheme, prefix)
        end
      end

      private

      def default_scheme(request, host)
        bare = host.to_s.sub(/:\d+\z/, "").downcase
        request.scheme == "http" && URL.loopback?(bare) ? "qrl" : "sqrl"
      end

      def build_endpoint(host, scheme, prefix)
        config_opts = options.reject { |k, _| ENDPOINT_KEYS.include?(k) || MIDDLEWARE_KEYS.include?(k) }
        config_opts[:host] = host
        config_opts[:scheme] = scheme
        config_opts[:path] = prefix + options[:path]
        config_opts[:callback_path] = prefix + options[:callback_path]
        config = Server::Config.new(**config_opts)
        handler = Server::Handler.new(config: config, stores: stores)
        Endpoint.new(handler: handler, session_key: options[:session_key], identity_key: options[:identity_key],
                     status_path: options[:status_path], callback_path: options[:callback_path],
                     script_path: options[:script_path], ip: options[:ip],
                     poll_requires_ip_match: options.fetch(:poll_requires_ip_match, true))
      end

      def complete(endpoint, request)
        completion = endpoint.callback(request)
        return failure(request) unless completion

        env = request.env
        on_login = options[:on_login]
        keep = options.fetch(:session_identity, on_login.nil?)
        env["rack.session"].delete(endpoint.identity_key) unless keep
        on_login&.call(env, completion.identity, completion.pending_login)
        redirect(after_login_url(request, completion))
      end

      def after_login_url(request, completion)
        return_to = completion.return_to
        return return_to if same_site_path?(return_to)

        target = options[:after_login]
        target = target.call(request.env, completion) if target.respond_to?(:call)
        target.to_s.empty? ? "#{request.script_name}/" : target
      end

      # A same-site, root-relative path. Rejects protocol-relative URLs (//host), the
      # backslash form browsers normalise to a slash (/\host), and control characters or
      # whitespace that URL parsers strip before interpreting the rest.
      def same_site_path?(path)
        path.is_a?(String) && path.match?(%r{\A/(?![/\\])}) && !path.match?(/[\x00-\x20\x7f\\]/)
      end

      def failure(request)
        if options[:failure_path]
          redirect(options[:failure_path])
        else
          [403, { "content-type" => "text/plain; charset=utf-8", "cache-control" => "no-store" },
           ["SQRL login failed or expired. Reload the login page and try again."]]
        end
      end

      def redirect(location)
        [303, { "location" => location, "content-type" => "text/html; charset=utf-8", "cache-control" => "no-store" },
         [%(<!doctype html><title>Redirecting</title><a href="#{CGI.escapeHTML(location)}">Continue</a>)]]
      end
    end
  end
end
