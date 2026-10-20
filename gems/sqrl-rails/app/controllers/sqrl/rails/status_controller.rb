# frozen_string_literal: true

module SQRL
  module Rails
    # Cookie-bound poll answered with +{"authenticated": bool, "next": url}+.
    class StatusController < ApplicationController
      def show
        render_rack(sqrl_endpoint.status(request))
      end
    end
  end
end
