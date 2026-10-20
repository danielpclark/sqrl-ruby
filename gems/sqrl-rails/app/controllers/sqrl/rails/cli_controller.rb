# frozen_string_literal: true

module SQRL
  module Rails
    # The SQRL endpoint: the client's signed POSTs. Authenticated by the protocol's own
    # signatures, so forgery protection does not apply.
    class CliController < ApplicationController
      include RateLimited

      skip_forgery_protection

      def create
        render_rack(sqrl_endpoint.cli(request))
      end
    end
  end
end
