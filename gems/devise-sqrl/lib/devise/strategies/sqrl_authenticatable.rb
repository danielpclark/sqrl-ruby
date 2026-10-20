# frozen_string_literal: true

require "devise/strategies/base"

module Devise
  # Devise's Warden strategy namespace.
  module Strategies
    # Completes a SQRL login on the mapping's callback route: claims the one-time CPS
    # token (or the browser's own, cookie-bound pending login after the poller saw it
    # authenticated), resolves or creates the resource and signs it in.
    class SQRLAuthenticatable < Base
      # Only the callback route of this mapping is handled.
      def valid?
        request.get? && request.path_info == Devise::SQRL.paths_for(mapping)[:callback]
      rescue StandardError
        false
      end

      # Claim the CPS token or the browser's pending login, apply the unknown-identity policy and
      # sign the resource in, or fail with a Devise failure key.
      def authenticate!
        endpoint = Devise::SQRL.endpoint_for(mapping, request)
        completion = endpoint.callback(request)
        return fail!(:sqrl_invalid) unless completion

        identity = completion.identity
        return fail!(:sqrl_disabled) if identity.disabled?
        return fail!(:sqrl_declined) if declined?(completion)

        resource = mapping.to.find_for_sqrl(identity) || resource_for_unknown(identity)
        return if halted?
        return fail!(:sqrl_unknown) unless resource
        return fail!(resource.inactive_message) unless resource.active_for_authentication?

        resource.remember_me = true if Devise.sqrl_remember_me && resource.respond_to?(:remember_me=)
        env["devise.sqrl.completion"] = completion
        success!(resource)
      end

      # Clearing CSRF data would log out any other scope; a SQRL callback is a fresh,
      # signed login so the default behaviour is kept.
      def clean_up_csrf?
        true
      end

      private

      # The client answered the site's +ask+ with the configured "deny" button.
      def declined?(completion)
        deny = ::SQRL::Rails.config.ask_deny_button
        !deny.nil? && completion.pending_login.btn == deny.to_i
      end

      def resource_for_unknown(identity)
        case Devise::SQRL.on_unknown_identity
        when :refuse
          nil
        when :link
          current = env["warden"].user(scope)
          return fail!(:sqrl_link_required) unless current.is_a?(mapping.to)

          current.link_sqrl_identity!(identity)
          current
        else
          mapping.to.create_for_sqrl!(identity)
        end
      end
    end
  end
end

Warden::Strategies.add(:sqrl_authenticatable, Devise::Strategies::SQRLAuthenticatable)
