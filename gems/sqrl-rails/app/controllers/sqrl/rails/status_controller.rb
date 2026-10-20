# frozen_string_literal: true

module SQRL
  module Rails
    # Cookie-bound poll answered with +{"authenticated": bool, "next": url}+.
    class StatusController < ApplicationController
      include RateLimited

      # The cookie-bound poll: is this browser's pending login authenticated yet?
      def show
        render_rack(sqrl_endpoint.status(request))
      end

      private

      def sqrl_rate_limit_scope
        :status
      end
    end
  end
end
