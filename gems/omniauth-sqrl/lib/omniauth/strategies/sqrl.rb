# frozen_string_literal: true

require "uri"
require "cgi"
require "json"

module OmniAuth
  # OmniAuth's strategy namespace.
  module Strategies
    # SQRL (Secure Quick Reliable Login) as an OmniAuth provider.
    #
    #   use OmniAuth::Builder do
    #     provider :sqrl, stores: SQRL::Server::Memory.stores, host: "example.com"
    #   end
    #
    # Phases:
    #
    # * request phase (+POST /auth/sqrl+): issues a login nut bound to the browser
    #   session and renders a login page (link, QR code, +sqrl.js+);
    # * other phase: serves the SQRL client's +POST /auth/sqrl/cli+, the browser's
    #   +GET /auth/sqrl/status+ poll and +GET /auth/sqrl/sqrl.js+, straight from the
    #   middleware (no CSRF layer of the application is involved);
    # * callback phase (+GET /auth/sqrl/callback?t=TOKEN+ reached by the SQRL client's
    #   Client Provided Session redirect, or +GET /auth/sqrl/callback+ by the poller):
    #   claims the one-time token or the cookie-bound pending login and builds the auth
    #   hash with +uid+ = the identity key (base64url) and the SQRL facts under
    #   +extra["sqrl"]+.
    #
    # Options (beyond OmniAuth's own): +stores:+ ({::SQRL::Server::Stores}; in-memory by
    # default, which is for development only), +host:+ (public host placed in
    # +sqrl://+ URLs; defaults to the request host), +insecure_http:+ (loopback-only
    # testing mode issuing +qrl://+ URLs; never on by default), +poll_requires_ip_match:+
    # (optional hardening, off by default), +path_extension:+, +nut_ttl:+,
    # +cps_token_ttl:+, +require_ip_match:+, +ask:+, +sin:+, +on_unknown_identity:+
    # (+:create+, +:link+ or +:refuse+), +link_user_ref:+ (callable +(env) -> ref+ naming
    # the signed-in user for +:link+), +login_block:+ (options of
    # {::SQRL::Rack::LoginBlock.render}), +title:+, +cancel_url:+, +info:+ (callable
    # +(identity) -> Hash+ to fill the info hash), +ip:+ (callable resolving the client
    # IP), +cli_path:+, +status_path:+, +script_path:+ (defaults under the provider's
    # path prefix) and +logger:+.
    class SQRL
      include OmniAuth::Strategy

      # Session key holding the pending-login id.
      SESSION_KEY = "omniauth.sqrl.pending_login"
      # Session key holding the logged-in identity key.
      IDENTITY_KEY = "omniauth.sqrl.identity"
      # Seconds the created/re-keyed facts of a pending login are remembered.
      FACTS_TTL = 3600
      # Maximum number of remembered fact records.
      FACTS_LIMIT = 10_000

      option :name, "sqrl"
      option :stores, nil
      option :host, nil
      option :scheme, nil
      option :insecure_http, false
      option :poll_requires_ip_match, false
      option :path_extension, nil
      option :nut_ttl, 300
      option :cps_token_ttl, 60
      option :require_ip_match, true
      option :ask, nil
      option :sin, nil
      option :on_unknown_identity, :create
      option :link_user_ref, nil
      option :login_block, {}
      option :title, "Sign in with SQRL"
      option :cancel_url, nil
      option :info, nil
      option :ip, nil
      option :cli_path, nil
      option :status_path, nil
      option :script_path, nil
      option :refresh_path, nil
      option :logger, nil
      # Hosts accepted when +host:+ is derived from the request (see
      # {::SQRL::Rack::HostResolver}); nil allows any, up to +host_cache_limit+ distinct ones.
      option :allowed_hosts, nil
      option :host_cache_limit, ::SQRL::Rack::HostResolver::DEFAULT_LIMIT
      # Rate-limit hooks, see {::SQRL::Server::Config}.
      option :before_issue, nil
      option :before_handle, nil
      option :prune_every, 1000

      # A {::SQRL::Rack::Endpoint} that remembers, per pending login, whether the
      # +ident+ created the account or re-keyed it, so the callback can report it.
      class Endpoint < ::SQRL::Rack::Endpoint
        # Cli on the OmniAuth strategy; same contract as +SQRL::Rack::Endpoint#cli+.
        def cli(request)
          result = handler.handle(nut: request.GET["nut"].to_s, body: form_body(request), ip: client_ip(request))
          SQRL.record_facts(result) if result.authenticated?
          [200, { "content-type" => "text/plain; charset=utf-8", "cache-control" => "no-store",
                  "x-sqrl-tif" => result.tif.to_hex }, [result.body]]
        rescue ::SQRL::Server::RateLimited => e
          rate_limited(e)
        end
      end

      @facts = {}
      @facts_mutex = Mutex.new

      class << self
        # Remember the outcome of an authenticating +ident+/+enable+ for its pending login.
        def record_facts(result)
          id = result.pending_login_id
          return unless id

          @facts_mutex.synchronize do
            prune_facts
            @facts[id] = { created: result.created?, rekeyed_from: result.rekeyed_from && ::SQRL::Util.b64u_encode(result.rekeyed_from),
                           tif: result.tif.value, at: Process.clock_gettime(Process::CLOCK_MONOTONIC) }
          end
        end

        # Take (and forget) the recorded facts for a pending login.
        def take_facts(id)
          @facts_mutex.synchronize { @facts.delete(id) }
        end

        private

        def prune_facts
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          @facts.delete_if { |_, f| now - f[:at] > FACTS_TTL }
          @facts.shift while @facts.size >= FACTS_LIMIT
        end
      end

      # The {::SQRL::Server::Stores} this provider uses: the +stores:+ option, or one
      # process-wide set of in-memory stores (OmniAuth::Builder rebuilds the strategy for
      # every request, so a per-instance default would forget everything).
      def stores
        options.stores || self.class.default_stores
      end

      @default_stores = nil

      class << self
        # Process-wide in-memory stores used when no +stores:+ option is given.
        def default_stores
          @facts_mutex.synchronize do
            @default_stores ||= begin
              unless ENV["RACK_ENV"] == "test" || ENV["RAILS_ENV"] == "test"
                OmniAuth.logger.warn("omniauth-sqrl is using in-memory stores; identities are lost on restart. " \
                                     "Pass stores: for production.")
              end
              ::SQRL::Server::Memory.stores
            end
          end
        end
      end

      # The identity that authenticated in the callback phase.
      attr_reader :identity, :completion

      uid { identity.idk_b64 }

      info do
        filler = options.info
        filler.respond_to?(:call) ? (filler.call(identity) || {}) : {}
      end

      credentials { {} }

      extra do
        facts = @facts || {}
        {
          "sqrl" => {
            "idk" => identity.idk_b64,
            "suk" => ::SQRL::Util.b64u_encode(identity.suk),
            "vuk" => ::SQRL::Util.b64u_encode(identity.vuk),
            "created" => facts.fetch(:created, false),
            "rekeyed_from" => facts[:rekeyed_from],
            "options" => { "sqrlonly" => identity.sqrlonly?, "hardlock" => identity.hardlock? },
            "disabled" => identity.disabled?,
            "logins" => identity.logins,
            "via" => completion.via.to_s,
            "user_ref" => identity.user_ref
          }
        }
      end

      # Renders the SQRL login page.
      def request_phase
        login = endpoint.issue(request, cancel_url: cancel_url, link_user_ref: link_user_ref)
        body = login_page(login)
        [200, { "content-type" => "text/html; charset=utf-8", "cache-control" => "no-store" }, [body]]
      rescue ::SQRL::Server::RateLimited => e
        headers = { "content-type" => "text/html; charset=utf-8", "cache-control" => "no-store" }
        headers["retry-after"] = e.retry_after.to_i.to_s if e.retry_after
        [429, headers, [%(<!doctype html><title>#{CGI.escapeHTML(options.title.to_s)}</title>) +
          ::SQRL::Rack::LoginBlock.unavailable(message: e.message)]]
      rescue ::SQRL::Rack::HostNotAllowed => e
        [400, { "content-type" => "text/plain; charset=utf-8", "cache-control" => "no-store" }, ["#{e.message}\n"]]
      end

      # Serves the SQRL endpoint, the status poll, the refresh endpoint and the browser
      # script.
      def other_phase
        if request.post? && on_path?(full_path(cli_path))
          endpoint.cli(request)
        elsif request.get? && on_path?(full_path(status_path))
          endpoint.status(request)
        elsif request.get? && on_path?(full_path(refresh_path))
          endpoint.refresh(request)
        elsif request.get? && on_path?(full_path(script_path))
          endpoint.script(request)
        else
          call_app!
        end
      rescue ::SQRL::Rack::HostNotAllowed => e
        [400, { "content-type" => "text/plain; charset=utf-8", "cache-control" => "no-store" }, ["#{e.message}\n"]]
      end

      # Completes the login from the CPS token or the cookie-bound pending login.
      def callback_phase
        completion = endpoint.callback(request)
        return fail!(failure_reason) unless completion

        session.delete(IDENTITY_KEY)
        @completion = completion
        @identity = completion.identity
        @facts = self.class.take_facts(completion.pending_login.id) || {}
        super
      end

      # Paths relative to the mount point (without +SCRIPT_NAME+).
      def cli_path = options.cli_path || "#{path_prefix}/#{name}/cli"
      # @return [String] full path of the status poll
      def status_path = options.status_path || "#{path_prefix}/#{name}/status"
      # @return [String] full path of +sqrl.js+
      def script_path = options.script_path || "#{path_prefix}/#{name}/sqrl.js"
      # @return [String] full path of the refresh endpoint
      def refresh_path = options.refresh_path || "#{path_prefix}/#{name}/refresh"

      # The request-scoped {Endpoint}.
      def endpoint
        @endpoint ||= Endpoint.new(handler: handler, session_key: SESSION_KEY, identity_key: IDENTITY_KEY,
                                   poll_requires_ip_match: options.poll_requires_ip_match ? true : false,
                                   status_path: status_path, callback_path: relative_callback_path,
                                   script_path: script_path, refresh_path: refresh_path, ip: options.ip)
      end

      # The {::SQRL::Server::Handler} for this request's host. Handlers are kept per
      # (options, host, scheme, mount) in a bounded cache shared by every strategy
      # instance built from the same options (OmniAuth::Builder rebuilds the strategy on
      # each request).
      #
      # @raise [::SQRL::Rack::HostNotAllowed] when a derived host is not acceptable
      def handler
        @handler ||= begin
          resolver = self.class.host_resolver_for(options)
          host, scheme = resolver.resolve(request)
          resolver.fetch([host, scheme, script_name.to_s]) do
            ::SQRL::Server::Handler.new(config: server_config(host, scheme), stores: stores)
          end
        end
      end

      # @return [SQRL::Server::Config] the protocol configuration for this request's host
      def server_config(host, scheme)
        ::SQRL::Server::Config.new(
          host: host, scheme: scheme, insecure_http: options.insecure_http ? true : false,
          path: full_path(cli_path), callback_path: full_path(relative_callback_path),
          path_extension: options.path_extension, nut_ttl: options.nut_ttl.to_i, cps_token_ttl: options.cps_token_ttl.to_i,
          require_ip_match: options.require_ip_match ? true : false, ask: options.ask, sin: options.sin,
          on_unknown_identity: options.on_unknown_identity.to_sym, logger: options.logger,
          allowed_hosts: options.allowed_hosts, prune_every: options.prune_every,
          before_issue: options.before_issue, before_handle: options.before_handle
        )
      end

      @host_resolvers = {}

      class << self
        # One {::SQRL::Rack::HostResolver} (and so one bounded handler cache) per distinct
        # provider configuration: OmniAuth::Builder rebuilds the strategy for every
        # request from the same option values, so equal configurations share it.
        def host_resolver_for(options)
          key = options.to_hash.reject { |k, _| k.to_s == "stores" }.merge("stores" => options.stores.object_id)
          @facts_mutex.synchronize do
            scheme = options.scheme || (options.insecure_http ? "qrl" : nil)
            @host_resolvers[key] ||= ::SQRL::Rack::HostResolver.new(host: options.host, scheme: scheme,
                                                                    allowed_hosts: options.allowed_hosts,
                                                                    limit: options.host_cache_limit,
                                                                    logger: options.logger || OmniAuth.logger)
          end
        end

        # Forget cached host resolvers and handlers (tests).
        def reset_host_resolvers!
          @facts_mutex.synchronize { @host_resolvers.clear }
        end
      end

      private

      # OmniAuth's +callback_path+ includes +SCRIPT_NAME+; the endpoint wants it without.
      def relative_callback_path
        path = callback_path
        prefix = script_name
        prefix.empty? || !path.start_with?(prefix) ? path : path[prefix.length..]
      end

      def full_path(path)
        "#{script_name}#{path}"
      end

      def cancel_url
        custom = options.cancel_url
        return custom.call(env) if custom.respond_to?(:call)
        return custom if custom

        origin = session["omniauth.origin"]
        safe_cancel_target?(origin) ? origin : "#{script_name}/"
      end

      # OmniAuth fills +omniauth.origin+ from +params[:origin]+ or the Referer, so it is
      # attacker-influenced: accept only a same-site root-relative path or an absolute
      # http(s) URL on this site's host; anything else (javascript:, other hosts) is dropped.
      def safe_cancel_target?(value)
        return false unless value.is_a?(String) && !value.empty?
        return !value.match?(/[\x00-\x20\x7f\\]/) if value.match?(%r{\A/(?![/\\])})

        uri = URI.parse(value)
        return false unless %w[http https].include?(uri.scheme.to_s.downcase) && uri.host

        hostport = uri.port && uri.port != uri.default_port ? "#{uri.host}:#{uri.port}" : uri.host
        request_host = request.host_with_port
        [request.host, request_host, handler.config.host].compact.any? do |h|
          h.casecmp?(hostport) || h.casecmp?(uri.host)
        end
      rescue URI::InvalidURIError
        false
      end

      def link_user_ref
        ref = options.link_user_ref
        ref.respond_to?(:call) ? ref.call(env) : ref
      end

      # Why the callback could not complete: a disabled identity when the pending login
      # was authenticated by one, otherwise a missing, foreign, used or expired token.
      def failure_reason
        id = session[SESSION_KEY]
        login = id && stores.pending_logins.find(id)
        if login&.authenticated?
          identity = stores.identities.find(login.authenticated_idk)
          return :sqrl_disabled if identity&.disabled?
        end
        :invalid_credentials
      end

      def login_block_options
        deep_symbolize(options.login_block.respond_to?(:to_hash) ? options.login_block.to_hash : {})
      end

      def deep_symbolize(value)
        case value
        when Hash then value.each_with_object({}) { |(k, v), h| h[k.to_sym] = deep_symbolize(v) }
        when Array then value.map { |v| deep_symbolize(v) }
        else value
        end
      end

      def login_page(login)
        block = ::SQRL::Rack::LoginBlock.render(
          login_url: login.url, status_url: endpoint.status_url(request), cancel_url: cancel_url,
          script_url: endpoint.script_url(request), **login_block_options
        )
        title = CGI.escapeHTML(options.title.to_s)
        <<~HTML
          <!doctype html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>#{title}</title>
            <style>
              body{font-family:system-ui,sans-serif;max-width:40em;margin:3em auto;line-height:1.5;padding:0 1em}
              .sqrl-login__link{display:inline-block;padding:.6em 1.2em;background:#007cc3;color:#fff;border-radius:.4em;text-decoration:none}
              .sqrl-login__qr svg{display:block;margin:1em 0;max-width:100%}
            </style>
          </head>
          <body>
            <h1>#{title}</h1>
            #{block}
          </body>
          </html>
        HTML
      end
    end
  end
end
