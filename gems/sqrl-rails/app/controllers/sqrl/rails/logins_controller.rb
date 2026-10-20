# frozen_string_literal: true

module SQRL
  module Rails
    # A stand-alone login page, for applications that do not embed
    # +sqrl_login_block+ in their own view.
    class LoginsController < ApplicationController
      layout "sqrl/rails/application"

      def new
        @return_to = params[:return_to].presence
      end
    end
  end
end
