# frozen_string_literal: true

module SQRL
  module Rails
    # View helpers available in the host application and the engine.
    module LoginHelper
      # The complete SQRL login markup (link, QR code, status text and script tag),
      # wired to the engine's endpoints. Each render issues a fresh login URL.
      #
      # @param return_to [String, nil] same-site path to land on after login (defaults to
      #   +params[:return_to]+ or Rails 8's +session[:return_to_after_authenticating]+)
      # @param cancel_url [String, nil]
      # @param link_user [Object, nil, false] user to link a new identity to; defaults to
      #   the signed-in user when known, +false+ disables linking
      # @param script [Boolean] append the +sqrl.js+ script tag
      # @param options [Hash] passed to {SQRL::Rack::LoginBlock.render}
      # @return [ActiveSupport::SafeBuffer]
      def sqrl_login_block(return_to: nil, cancel_url: nil, link_user: nil, script: true, **options)
        login = sqrl_login_url(return_to: return_to, cancel_url: cancel_url, link_user: link_user)
        SQRL::Rack::LoginBlock.render(login_url: login.url, status_url: sqrl_status_path,
                                      cancel_url: cancel_url, script_url: (sqrl_script_path if script),
                                      refresh_url: sqrl_refresh_path,
                                      **options).html_safe
      end

      # Issue (once per request) and return the +sqrl://+ login URL.
      #
      # @return [SQRL::Server::LoginURL]
      def sqrl_login_url(return_to: nil, cancel_url: nil, link_user: nil)
        @sqrl_login_url ||= begin
          return_to ||= sqrl_default_return_to
          link_ref = link_user == false ? nil : SQRL::Rails.user_ref(link_user || sqrl_linkable_user)
          SQRL::Rails.endpoint_for(request).issue(request, return_to: return_to, cancel_url: cancel_url,
                                                           link_user_ref: link_ref)
        end
      end

      # The QR code of the login URL as inline SVG.
      def sqrl_qr_svg(**options)
        SQRL::Rack::QR.svg(sqrl_login_url.url, **options).html_safe
      end

      # +<script src="/sqrl/sqrl.js" defer>+
      def sqrl_script_tag
        SQRL::Rack::LoginBlock.script_tag(src: sqrl_script_path).html_safe
      end

      def sqrl_status_path = SQRL::Rails.path_for(:status, script_name: sqrl_host_script_name)
      # The identity-management page of the engine (list and unlink SQRL identities).
      def sqrl_identities_path = SQRL::Rails.path_for(:identities, script_name: sqrl_host_script_name)
      def sqrl_callback_path = SQRL::Rails.path_for(:callback, script_name: sqrl_host_script_name)
      def sqrl_script_path = SQRL::Rails.path_for(:script, script_name: sqrl_host_script_name)
      def sqrl_refresh_path = SQRL::Rails.path_for(:refresh, script_name: sqrl_host_script_name)

      private

      # The host application's own prefix (its relative URL root), excluding the engine
      # mount when rendering inside the engine.
      def sqrl_host_script_name
        name = request.script_name.to_s
        mount = SQRL::Rails.mount_path
        name.end_with?(mount) ? name[0, name.length - mount.length] : name
      end

      def sqrl_default_return_to
        candidate = params[:return_to].presence || (session[:return_to_after_authenticating] if respond_to?(:session))
        SignIn.same_site_path?(candidate) ? candidate : nil
      rescue StandardError
        nil
      end

      def sqrl_linkable_user
        return nil unless SQRL::Rails.config.on_unknown_identity == :link

        SignIn.current_user(controller)
      rescue StandardError
        nil
      end
    end
  end
end
