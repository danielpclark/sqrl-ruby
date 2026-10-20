# frozen_string_literal: true

module SQRL
  module Rails
    # Lets a signed-in user see the SQRL identities attached to their account and unlink
    # one. Unlinking detaches the identity from the user (the site keeps the protocol
    # association, so the SQRL client still "knows" the site); the next login with that
    # identity is treated as an unknown identity again.
    #
    # The signed-in user comes from the host's +Authentication+ concern (Rails 8), from
    # +config.sqrl.current_user+, or from the session fallback of {SignIn}.
    class IdentitiesController < ApplicationController
      include RateLimited

      concern = SQRL::Rails.host_authentication_concern
      include concern if concern

      layout "sqrl/rails/application"

      before_action :require_sqrl_user

      # List the current user's SQRL identities.
      def index
        @identities = Identity.active.for_user(@sqrl_user).order(:created_at)
        @current_idk = sqrl_endpoint.current_identity(request)&.idk_b64
      end

      # Unlink one of the current user's SQRL identities.
      def destroy
        identity = Identity.active.for_user(@sqrl_user).find_by(id: params[:id])
        if identity
          current = sqrl_endpoint.current_identity(request)&.idk_b64
          identity.update!(user: nil)
          sqrl_endpoint.logout(request) if current && current == identity.idk
          flash[:notice] = I18n.t("sqrl.identities.unlinked", default: "SQRL identity unlinked.")
        else
          flash[:alert] = I18n.t("sqrl.identities.not_found", default: "That SQRL identity is not linked to your account.")
        end
        redirect_to engine_path(:identities), status: :see_other
      end

      private

      def sqrl_rate_limit_scope
        :identities
      end

      def require_sqrl_user
        @sqrl_user = SignIn.current_user(self)
        return if @sqrl_user

        flash[:alert] = I18n.t("sqrl.identities.sign_in_required", default: "Sign in to manage your SQRL identities.")
        redirect_to(sqrl_config.failure_path || engine_path(:login), allow_other_host: false)
      end
    end
  end
end
