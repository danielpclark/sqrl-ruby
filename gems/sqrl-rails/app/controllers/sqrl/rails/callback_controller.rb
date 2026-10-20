# frozen_string_literal: true

module SQRL
  module Rails
    # Completes a login: with +t=+ (the one-time CPS token the SQRL client sent the
    # browser to) or without it (the browser's own pending login, after the poller saw
    # it authenticated). Resolves or creates the user, signs them in through the
    # configured adapter and redirects.
    class CallbackController < ApplicationController
      include RateLimited

      concern = SQRL::Rails.host_authentication_concern
      if concern
        include concern

        allow_unauthenticated_access if respond_to?(:allow_unauthenticated_access)
      end

      def show
        completion = sqrl_endpoint.callback(request)
        return failure("SQRL login failed or expired. Please try again.") unless completion
        return failure(I18n.t("sqrl.callback.declined", default: "You declined the SQRL login."), completion) if declined?(completion)

        user = resolve_user(completion)
        return failure("This SQRL identity is not linked to an account.", completion) unless user

        sign_in = SQRL::Rails.config.sign_in || SignIn.method(:default)
        sign_in.call(self, completion.identity, user)
        redirect_to SignIn.after(self, completion), allow_other_host: false
      rescue SQRL::Rails::Error, ActiveRecord::RecordInvalid, ActiveRecord::RecordNotSaved,
             ActionController::Redirecting::UnsafeRedirectError => e
        failure(e.message, completion)
      end

      private

      def sqrl_rate_limit_scope
        :callback
      end

      # The client answered the site's +ask+ with the button configured as "deny".
      def declined?(completion)
        deny = sqrl_config.ask_deny_button
        !deny.nil? && completion.pending_login.btn == deny.to_i
      end

      # The user behind an identity; for a brand-new identity apply the configured
      # policy.
      def resolve_user(completion)
        identity = completion.identity
        user = find_user(identity)
        return user if user

        case sqrl_config.on_unknown_identity
        when :refuse
          nil
        when :link
          link_to_current_user(identity)
        else
          create_user(identity)
        end
      end

      def find_user(identity)
        return sqrl_config.find_user.call(identity) if sqrl_config.find_user

        SQRL::Rails.user_from_ref(identity.user_ref)
      end

      def create_user(identity)
        user = sqrl_config.create_user ? sqrl_config.create_user.call(identity) : UserFactory.call(identity)
        attach(identity, user)
      end

      def link_to_current_user(identity)
        user = SignIn.current_user(self)
        return nil unless user

        attach(identity, user)
      end

      def attach(identity, user)
        return nil unless user

        SQRL::Rails.stores.identities.update(identity.idk, user_ref: SQRL::Rails.user_ref(user))
        user
      end

      # +completion+ is passed when the pending login was already consumed: the endpoint
      # recorded the identity in the session at that point, so a failed sign-in must clear
      # it again, otherwise the controller helpers would report a refused identity as
      # authenticated.
      def failure(message, completion = nil)
        sqrl_endpoint.logout(request) if completion
        flash[:alert] = message if respond_to?(:flash)
        redirect_to(sqrl_config.failure_path || engine_path(:login), allow_other_host: false)
      end
    end
  end
end
