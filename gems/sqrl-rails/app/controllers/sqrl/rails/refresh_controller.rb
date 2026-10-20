# frozen_string_literal: true

module SQRL
  module Rails
    # Hands the login page a fresh login URL (and QR code) for its browser session when
    # the previous nut expired, as JSON; +sqrl.js+ calls it through +SQRL.refresh+.
    class RefreshController < ApplicationController
      include RateLimited

      # Issue a fresh login URL for the browser's session as JSON (used by +SQRL.refresh+).
      def show
        render_rack(sqrl_endpoint.refresh(request))
      end

      private

      def sqrl_rate_limit_scope
        :refresh
      end
    end
  end
end
