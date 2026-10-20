# frozen_string_literal: true

module SQRL
  module Rails
    # Completes a login: with +t=+ (the one-time CPS token the SQRL client sent the
    # browser to) or without it (the browser's own pending login, after the poller saw
    # it authenticated). Resolves or creates the user, signs them in through the
    # configured adapter and redirects.
    class CallbackController < ApplicationController
      concern = SQRL::Rails.host_authentication_concern
      if concern
        include concern
        allow_unauthenticated_access if respond_to?(:allow_unauthenticated_access)
      end

      def show
        completion = sqrl_endpoint.callback(request)
        return failure("SQRL login failed or expired. Please try again.") unless completion

        user = resolve_user(completion)
        return failure("This SQRL identity is not linked to an account.") unless user

        sign_in = SQRL::Rails.config.sign_in || SignIn.method(:default)
        sign_in.call(self, completion.identity, user)
        redirect_to SignIn.after(self, completion), allow_other_host: false
      rescue SQRL::Rails::Error => e
        failure(e.message)
      end

      private

      def config
        SQRL::Rails.config
      end

      # The host's Authentication concern uses the host's route helpers (root_url,
      # new_session_path); resolve them through the main_app proxy.
      def method_missing(name, *args, &block)
        if host_route_helper?(name)
          main_app.public_send(name, *args, &block)
        else
          super
        end
      end

      def respond_to_missing?(name, include_private = false)
        host_route_helper?(name) || super
      end

      def host_route_helper?(name)
        name.to_s.match?(/_(url|path)\z/) && respond_to?(:main_app) && main_app.respond_to?(name)
      end

      # The user behind an identity; for a brand-new identity apply the configured
      # policy.
      def resolve_user(completion)
        identity = completion.identity
        user = find_user(identity)
        return user if user

        case config.on_unknown_identity
        when :refuse
          nil
        when :link
          link_to_current_user(identity)
        else
          create_user(identity)
        end
      end

      def find_user(identity)
        return config.find_user.call(identity) if config.find_user

        SQRL::Rails.user_from_ref(identity.user_ref)
      end

      def create_user(identity)
        user = config.create_user ? config.create_user.call(identity) : UserFactory.call(identity)
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

      def failure(message)
        flash[:alert] = message if respond_to?(:flash)
        redirect_to(config.failure_path || engine_path(:login), allow_other_host: false)
      end
    end
  end
end
