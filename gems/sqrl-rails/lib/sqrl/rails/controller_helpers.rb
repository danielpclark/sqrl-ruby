# frozen_string_literal: true

module SQRL
  module Rails
    # Included into +ActionController::Base+ of the host application.
    module ControllerHelpers
      extend ActiveSupport::Concern

      included do
        helper_method :current_sqrl_identity, :sqrl_authenticated? if respond_to?(:helper_method)
      end

      # The {SQRL::Rack::Endpoint} for this request.
      def sqrl_endpoint
        SQRL::Rails.endpoint_for(request)
      end

      # The SQRL identity record this browser session logged in with, or nil.
      def current_sqrl_identity
        return @current_sqrl_identity if defined?(@current_sqrl_identity)

        @current_sqrl_identity = sqrl_endpoint.current_identity(request)
      end

      def sqrl_authenticated?
        !current_sqrl_identity.nil?
      end

      # Forget the SQRL login in this browser session (call it from your logout action).
      def sqrl_logout!
        sqrl_endpoint.logout(request)
        remove_instance_variable(:@current_sqrl_identity) if defined?(@current_sqrl_identity)
        nil
      end
    end
  end
end
