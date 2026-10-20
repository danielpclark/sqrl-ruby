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
    # wins), +failure_path:+ (redirect target when the callback fails; 403 when nil),
    # +session_identity:+ (store the +idk+ in the session; defaults to true when
    # +on_login+ is nil), +refresh_path:+ (JSON endpoint handing the page a fresh login
    # URL), +allowed_hosts:+ and +host_cache_limit:+ (see {HostResolver}; derived hosts
    # beyond the limit get 400), and the rate-limit hooks +before_issue:+ /
    # +before_handle:+ (see {Server::Config}; a hook raising {Server::RateLimited} turns
    # into HTTP 429).
    class Middleware
      DEFAULTS = {
        path: "/sqrl/cli", callback_path: "/sqrl/callback", status_path: "/sqrl/status", script_path: "/sqrl/sqrl.js",
        refresh_path: "/sqrl/refresh", session_key: Endpoint::SESSION_KEY, identity_key: Endpoint::IDENTITY_KEY,
        after_login: "/"
      }.freeze
      ENDPOINT_KEYS = %i[status_path script_path refresh_path session_key identity_key ip poll_requires_ip_match].freeze
      MIDDLEWARE_KEYS = %i[stores on_login after_login failure_path session_identity host_cache_limit].freeze

      # @param app [#call]
      # @param options [Hash, #call] options, or a callable returning them (resolved on
      #   the first request, which lets a Sinatra app finish its +set+ calls first)
      def initialize(app, options = {})
        @app = app
        @raw_options = options
        @mutex = Mutex.new
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
        elsif request.get? && path == endpoint.refresh_path
          endpoint.refresh(request)
        else
          env["sqrl.server"] = Facade.new(endpoint, request)
          @app.call(env)
        end
      rescue HostNotAllowed => e
        [400, { "content-type" => "text/plain; charset=utf-8", "cache-control" => "no-store" }, ["#{e.message}\n"]]
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

      # The {HostResolver} deciding host and scheme per request and bounding the
      # per-host endpoint cache.
      def host_resolver
        return @host_resolver if @host_resolver

        opts = options # resolved outside the lock: it takes the same mutex
        @mutex.synchronize do
          @host_resolver ||= HostResolver.new(host: opts[:host], scheme: opts[:scheme],
                                              allowed_hosts: opts[:allowed_hosts],
                                              limit: opts[:host_cache_limit], logger: opts[:logger])
        end
      end

      # One {Endpoint} per (host, scheme, mount prefix) combination, built lazily.
      #
      # @raise [HostNotAllowed] when the request host is not acceptable
      def endpoint_for(request)
        host, scheme = host_resolver.resolve(request)
        prefix = request.script_name.to_s
        host_resolver.fetch([host, scheme, prefix]) { build_endpoint(host, scheme, prefix) }
      end

      private

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
                     script_path: options[:script_path], refresh_path: options[:refresh_path], ip: options[:ip],
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
