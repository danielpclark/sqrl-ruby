# frozen_string_literal: true

module SQRL
  module Rack
    # Raised when a request's host may not be used to issue SQRL URLs. Integrations answer
    # 400.
    class HostNotAllowed < Error; end

    # Decides which host (with port) and scheme a request's SQRL URLs are issued for, and
    # bounds the set of hosts an integration keeps per-host state for.
    #
    # The host is the string every identity key is derived from, so a deployment should
    # configure it explicitly. When it is not configured the request's +Host+ header is
    # used: a warning is logged once, the host must pass +allowed_hosts+ when that list is
    # given, and at most +limit+ distinct hosts are accepted per process; further ones
    # raise {HostNotAllowed} rather than growing the per-host caches without bound.
    #
    # {#fetch} is the bounded, thread-safe cache integrations keep their per-host handler
    # or endpoint in; a configured host never counts against the limit.
    class HostResolver
      DEFAULT_LIMIT = 16

      attr_reader :host, :scheme, :limit

      # @param host [String, nil] the configured public host (with port), or nil to derive
      # @param scheme [String, nil] +sqrl+ (the default and the only standard scheme) or
      #   +qrl+ for the loopback-only +insecure_http+ testing mode; never derived from the request
      # @param allowed_hosts [Array<String, Regexp>, nil] accepted derived hosts
      # @param limit [Integer] maximum number of distinct derived hosts kept
      # @param logger [#warn, nil] receives the one-time warning; +Kernel#warn+ when nil
      def initialize(host: nil, scheme: nil, allowed_hosts: nil, limit: DEFAULT_LIMIT, logger: nil)
        @host = host&.to_s
        @scheme = scheme&.to_s
        @allowed_hosts = allowed_hosts
        @limit = limit || DEFAULT_LIMIT
        @logger = logger
        @mutex = Mutex.new
        @cache = {}
        @warned = false
      end

      # @return [Boolean] whether the host comes from configuration rather than requests
      def configured?
        !@host.nil? && !@host.empty?
      end

      # The host (with port) and scheme for a request.
      #
      # @param request [Rack::Request]
      # @return [Array(String, String)]
      # @raise [HostNotAllowed] when a derived host is not allowed
      def resolve(request)
        host = configured? ? @host : derived_host(request)
        [host, @scheme || "sqrl"]
      end

      # Fetch (or build with the block) the cached object for +key+, whose first element
      # must be the host. Once +limit+ distinct derived hosts are cached, a key for a new
      # host raises {HostNotAllowed} (keys for already-known hosts, for example other
      # mount prefixes, are still accepted).
      def fetch(key)
        @mutex.synchronize do
          return @cache[key] if @cache.key?(key)

          host = host_of(key)
          if !configured? && known_hosts.size >= @limit && !known_hosts.include?(host)
            raise HostNotAllowed, "too many distinct request hosts (limit #{@limit}); configure host: explicitly"
          end

          @cache[key] = yield
        end
      end

      # Distinct hosts currently cached.
      def known_hosts
        @cache.keys.map { |k| host_of(k) }.uniq
      end

      # Number of cached entries.
      def size
        @mutex.synchronize { @cache.size }
      end

      # Whether +host+ (with or without port) passes +allowed_hosts+ (always when none).
      def allowed?(host)
        Server::Config.new(host: "placeholder.invalid", allowed_hosts: @allowed_hosts).host_allowed?(host)
      end

      private

      def host_of(key)
        key.is_a?(Array) ? key.first : key
      end

      def derived_host(request)
        host = request.host_with_port.to_s
        raise HostNotAllowed, "request has no Host" if host.empty?
        raise HostNotAllowed, "host #{host.inspect} is not in allowed_hosts" unless allowed?(host)

        warn_once(host)
        host
      end

      def warn_once(host)
        return if @warned

        @warned = true
        message = "[sqrl] host not configured; deriving it from the request (#{host}). Identities are keyed " \
                  "by host, so set host: explicitly in production."
        @logger.respond_to?(:warn) ? @logger.warn(message) : Kernel.warn(message)
      end
    end
  end
end
