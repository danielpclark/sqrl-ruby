# frozen_string_literal: true

module SQRL
  module Server
    # Configuration of a {Handler}.
    #
    #   config = SQRL::Server::Config.new(host: "example.com") do |c|
    #     c.on_unknown_identity = :link
    #     c.ask = SQRL::Ask.new(message: "Log in to Example?", buttons: [{ label: "Yes" }, { label: "No" }])
    #   end
    class Config
      UNKNOWN_IDENTITY_POLICIES = %i[create link refuse].freeze
      SCHEMES = %w[sqrl qrl].freeze

      # Host (with optional port) placed in issued +sqrl://+ URLs. Must be the public host.
      attr_accessor :host
      # Path of the SQRL endpoint, also used in +qry=+.
      attr_accessor :path
      # Path of the CPS callback used by the default +cps_url+ builder.
      attr_accessor :callback_path
      # +sqrl+, or +qrl+ for plain-http loopback development.
      attr_accessor :scheme
      # +x=N+ path extension to scope identities to a path prefix (nil for none).
      attr_accessor :path_extension
      # Lifetime in seconds of nuts (login page and per-response).
      attr_accessor :nut_ttl
      # Lifetime in seconds of the one-time CPS landing token.
      attr_accessor :cps_token_ttl
      # Enforce +IPS_MATCHED+ unless the client sends +noiptest+.
      attr_accessor :require_ip_match
      # {Ask} to pose in query replies, or a callable +(context) -> Ask or nil+.
      attr_accessor :ask
      # Secret index challenge (+sin=+): a String, or a callable +(context) -> String or nil+.
      attr_accessor :sin
      # +:create+ (auto account), +:link+ (needs a pending login with +link_user_ref+) or
      # +:refuse+.
      attr_accessor :on_unknown_identity
      # Callable +(identity, pending_login, command)+ invoked after a successful +ident+ or
      # +enable+.
      attr_accessor :on_authenticated
      # Callable +(token, pending_login) -> String+ building the CPS +url=+.
      attr_accessor :cps_url
      # Callable returning the current Time (injectable for tests).
      attr_accessor :clock
      # Logger (anything responding to +debug+/+info+/+warn+), or nil.
      attr_accessor :logger

      def initialize(host: nil, path: "/sqrl/cli", callback_path: "/sqrl/callback", scheme: "sqrl",
                     path_extension: nil, nut_ttl: 300, cps_token_ttl: 60, require_ip_match: true,
                     ask: nil, sin: nil, on_unknown_identity: :create, on_authenticated: nil,
                     cps_url: nil, clock: nil, logger: nil)
        @host = host
        @path = path
        @callback_path = callback_path
        @scheme = scheme
        @path_extension = path_extension
        @nut_ttl = nut_ttl
        @cps_token_ttl = cps_token_ttl
        @require_ip_match = require_ip_match
        @ask = ask
        @sin = sin
        @on_unknown_identity = on_unknown_identity
        @on_authenticated = on_authenticated
        @cps_url = cps_url
        @clock = clock || -> { Time.now }
        @logger = logger
        yield self if block_given?
        validate!
      end

      # Raise ArgumentError when a value is unusable.
      def validate!
        raise ArgumentError, "host is required" if @host.nil? || @host.to_s.strip.empty?
        raise ArgumentError, "host must not contain a scheme or path" if @host.match?(%r{://|/})
        raise ArgumentError, "path must start with /" unless @path.to_s.start_with?("/")
        raise ArgumentError, "callback_path must start with /" unless @callback_path.to_s.start_with?("/")
        raise ArgumentError, "scheme must be sqrl or qrl" unless SCHEMES.include?(@scheme)
        if @scheme == "qrl" && !URL.loopback?(@host.to_s.split(":").first.to_s.downcase) &&
           !@host.start_with?("[")
          raise ArgumentError, "qrl:// (plain http) is only allowed for loopback hosts"
        end
        unless @path_extension.nil? || (@path_extension.is_a?(Integer) && @path_extension.positive?)
          raise ArgumentError, "path_extension must be nil or a positive Integer"
        end
        raise ArgumentError, "nut_ttl must be a positive number" unless positive_number?(@nut_ttl)
        raise ArgumentError, "cps_token_ttl must be a positive number" unless positive_number?(@cps_token_ttl)
        unless UNKNOWN_IDENTITY_POLICIES.include?(@on_unknown_identity)
          raise ArgumentError, "on_unknown_identity must be one of #{UNKNOWN_IDENTITY_POLICIES.join(', ')}"
        end
        raise ArgumentError, "ask must be an SQRL::Ask or a callable" unless valid_ask?
        raise ArgumentError, "sin must be a String or a callable" unless valid_sin?
        raise ArgumentError, "on_authenticated must be callable" unless @on_authenticated.nil? || callable?(@on_authenticated)
        raise ArgumentError, "cps_url must be callable" unless @cps_url.nil? || callable?(@cps_url)
        raise ArgumentError, "clock must be callable" unless callable?(@clock)

        true
      end

      # +https+ (or +http+ for +qrl+).
      def http_scheme
        @scheme == "qrl" ? "http" : "https"
      end

      # +https://host+
      def origin
        "#{http_scheme}://#{@host}"
      end

      def now
        @clock.call
      end

      # Resolve the +ask+ setting for a request context.
      def ask_for(context)
        callable?(@ask) ? @ask.call(context) : @ask
      end

      # Resolve the +sin+ setting for a request context.
      def sin_for(context)
        value = callable?(@sin) ? @sin.call(context) : @sin
        value.nil? ? nil : value.to_s
      end

      # Build the CPS +url=+ for a token.
      def cps_url_for(token, pending_login)
        return @cps_url.call(token, pending_login) if @cps_url

        "#{origin}#{@callback_path}?t=#{token}"
      end

      def require_ip_match? = @require_ip_match ? true : false

      private

      def positive_number?(v)
        v.is_a?(Numeric) && v.positive?
      end

      def callable?(v)
        v.respond_to?(:call)
      end

      def valid_ask?
        @ask.nil? || @ask.is_a?(Ask) || callable?(@ask)
      end

      def valid_sin?
        @sin.nil? || @sin.is_a?(String) || callable?(@sin)
      end
    end
  end
end
