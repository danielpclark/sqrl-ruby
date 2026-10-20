# frozen_string_literal: true

module SQRL
  module Rails
    # A stand-alone login page, for applications that do not embed
    # +sqrl_login_block+ in their own view.
    class LoginsController < ApplicationController
      include RateLimited

      layout "sqrl/rails/application"

      # Render the stand-alone login page.
      def new
        @return_to = params[:return_to].presence
      end

      private

      def sqrl_rate_limit_scope
        :login
      end
    end
  end
end
