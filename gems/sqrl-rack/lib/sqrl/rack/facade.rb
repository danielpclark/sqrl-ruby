# frozen_string_literal: true

module SQRL
  module Rack
    # Request-scoped view of SQRL for the application, available as
    # +env["sqrl.server"]+ on every request the {Middleware} passes through.
    class Facade
      attr_reader :endpoint, :request

      def initialize(endpoint, request)
        @endpoint = endpoint
        @request = request
      end

      # The login URL for this page view (issued once per request).
      #
      # @return [Server::LoginURL]
      def login_url(return_to: nil, cancel_url: nil, link_user_ref: nil)
        @login_url ||= @endpoint.issue(@request, return_to: return_to, cancel_url: cancel_url,
                                                 link_user_ref: link_user_ref)
      end

      # Full login markup (link, QR, status text, script tag). Options are those of
      # {LoginBlock.render} plus +return_to:+, +link_user_ref:+ and +script:+ (false to
      # leave the script tag out).
      #
      # When a +before_issue+ hook refuses the request ({Server::RateLimited}) the block
      # degrades to a short "try again later" message instead of raising.
      def login_block(return_to: nil, cancel_url: nil, link_user_ref: nil, script: true, **options)
        login = login_url(return_to: return_to, cancel_url: cancel_url, link_user_ref: link_user_ref)
        LoginBlock.render(login_url: login.url, status_url: @endpoint.status_url(@request),
                          cancel_url: cancel_url, script_url: script ? @endpoint.script_url(@request) : nil,
                          refresh_url: @endpoint.refresh_url(@request), **options)
      rescue Server::RateLimited => e
        LoginBlock.unavailable(message: e.message, css_class: options.fetch(:css_class, "sqrl-login"))
      end

      # @return [String] a +<script>+ tag loading +sqrl.js+ from this site
      def script_tag
        LoginBlock.script_tag(src: @endpoint.script_url(@request))
      end

      # @return [String] the login URL as an SVG QR code (see {QR.svg})
      def qr_svg(**options)
        QR.svg(login_url.url, **options)
      end

      # @return [String] see {Endpoint#status_url}
      def status_url = @endpoint.status_url(@request)
      # @return [String] see {Endpoint#callback_url}
      def callback_url = @endpoint.callback_url(@request)
      # @return [String] see {Endpoint#script_url}
      def script_url = @endpoint.script_url(@request)
      # @return [String] see {Endpoint#refresh_url}
      def refresh_url = @endpoint.refresh_url(@request)

      # The SQRL identity record logged in to this browser session, or nil.
      def identity
        return @identity if defined?(@identity)

        @identity = @endpoint.current_identity(@request)
      end

      # @return [String, nil] the logged-in identity key as base64url
      def idk_b64 = identity&.idk_b64

      def authenticated?
        !identity.nil?
      end

      # Forget the SQRL login in this session.
      def logout!
        @endpoint.logout(@request)
        remove_instance_variable(:@identity) if defined?(@identity)
        nil
      end
    end
  end
end
