# frozen_string_literal: true

module SQRL
  module Rails
    # A small, version-independent rate limiter for the engine's public actions,
    # configured through +config.sqrl.rate_limit = { to: 60, within: 1.minute }+.
    # Requests are counted per client IP (or per +by:+ callable) in +Rails.cache+ (or the
    # +cache:+ option); over the limit the action answers 429. +nil+ (the default)
    # disables it. Works on Rails 7.1 as well as on versions that have their own
    # +rate_limit+ macro.
    module RateLimited
      extend ActiveSupport::Concern

      included do
        before_action :sqrl_enforce_rate_limit
      end

      # The configured limit for an action name, or nil.
      #
      # @param action [Symbol] +:cli+, +:login+, +:status+, +:callback+, +:identities+
      # @return [Hash, nil]
      def self.limit_for(action)
        limit = SQRL::Rails.config.rate_limit
        return nil unless limit.is_a?(Hash) && limit[:to] && limit[:within]

        only = limit[:only]
        return nil if only && !Array(only).map(&:to_sym).include?(action.to_sym)

        limit
      end

      private

      # Name used to scope the limit; controllers override it.
      def sqrl_rate_limit_scope
        :cli
      end

      def sqrl_enforce_rate_limit
        limit = RateLimited.limit_for(sqrl_rate_limit_scope)
        return unless limit

        by = limit[:by] ? limit[:by].call(request) : request.remote_ip
        cache = limit[:cache] || ::Rails.cache
        window = limit[:within].to_i
        bucket = (Time.now.to_i / window).to_s
        key = "sqrl:rate_limit:#{sqrl_rate_limit_scope}:#{by}:#{bucket}"
        count = cache.increment(key, 1, expires_in: window)
        if count.nil?
          # Stores without increment support (or a missing key on some stores): fall back
          # to a read/write cycle. Not atomic, but still bounded.
          count = cache.read(key).to_i + 1
          cache.write(key, count, expires_in: window)
        end
        return if count <= limit[:to].to_i

        response.set_header("retry-after", (window - (Time.now.to_i % window)).to_s)
        head :too_many_requests
      end
    end
  end
end
