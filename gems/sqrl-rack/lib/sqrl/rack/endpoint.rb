# frozen_string_literal: true

require "json"

module SQRL
  module Rack
    # Framework-neutral request handlers around a {Server::Handler}: issue login URLs,
    # answer the SQRL client's POST, the browser's status poll and the login callback.
    # {Middleware} drives these for plain Rack; the Rails engine calls them from
    # controllers.
    #
    # The pending login id lives in the browser session under +session_key+; the
    # identity of a completed login is written under +identity_key+ by {#callback}.
    class Endpoint
      # Default session key holding the pending-login id.
      SESSION_KEY = "sqrl.pending_login"
      # Default session key holding the logged-in identity key (base64url).
      IDENTITY_KEY = "sqrl.identity"

      # What {#callback} returns when a login completes.
      Completion = Struct.new(:identity, :pending_login, :via, keyword_init: true) do
        # @return [String] the identity key as base64url
        def idk_b64 = identity.idk_b64
        # @return [String, nil] the same-site return path captured when the login page was issued
        def return_to = pending_login.return_to
        def cps? = via == :cps
      end

      attr_reader :handler, :config, :session_key, :identity_key, :status_path, :callback_path, :script_path,
                  :refresh_path

      # Headers of a 429 answer.
      RATE_LIMITED_HEADERS = { "content-type" => "text/plain; charset=utf-8", "cache-control" => "no-store" }.freeze

      # @param handler [Server::Handler]
      # @param status_path [String] app-relative path of the JSON poll endpoint
      # @param callback_path [String] app-relative path of the login callback
      #   (+config.callback_path+ must be the public form of the same path)
      # @param script_path [String] app-relative path serving +sqrl.js+
      # @param ip [#call, nil] +(request) -> String+ resolving the client IP; defaults to
      #   +Rack::Request#ip+
      # +poll_requires_ip_match+ (default false): when true, a login completed through the
      # browser's own cookie (the poll path, no CPS token) counts only when the SQRL
      # client's IP matched the browser's. This is an optional hardening against a client
      # that sent +noiptest+ being tricked into authenticating a login page opened by
      # someone else; it also refuses legitimate logins from a phone on another network,
      # which is why it is off by default. CPS completions are unaffected.
      # +refresh_path+ serves {#refresh}: a JSON endpoint the page calls (through
      # +SQRL.refresh+) to swap an expired login URL for a fresh one without a reload.
      def initialize(handler:, session_key: SESSION_KEY, identity_key: IDENTITY_KEY, status_path: "/sqrl/status",
                     callback_path: nil, script_path: "/sqrl/sqrl.js", refresh_path: "/sqrl/refresh", ip: nil,
                     poll_requires_ip_match: false)
        @handler = handler
        @refresh_path = refresh_path
        @poll_requires_ip_match = poll_requires_ip_match
        @config = handler.config
        @session_key = session_key
        @identity_key = identity_key
        @status_path = status_path
        @callback_path = callback_path || handler.config.callback_path
        @script_path = script_path
        @ip = ip
      end

      # Issue a fresh login URL and remember its pending login in the browser session.
      #
      # @param request [Rack::Request]
      # @param return_to [String, nil] where the browser goes after login (same-site path)
      # @param cancel_url [String, nil] encoded into +can=+
      # @param link_user_ref [Object, nil] signed-in user to link a new identity to
      # @return [Server::LoginURL]
      def issue(request, return_to: nil, cancel_url: nil, link_user_ref: nil)
        session = session_of(request)
        login = @handler.new_login_url(ip: client_ip(request), cancel_url: cancel_url, return_to: return_to,
                                       link_user_ref: link_user_ref)
        session[@session_key] = login.pending_login_id
        login
      end

      # The pending login id stored in the browser session, if any.
      def pending_login_id(request)
        session = request.env["rack.session"]
        session && session[@session_key]
      end

      # Handle the SQRL client's POST. Always 200 with the protocol body; TIF carries
      # failures.
      #
      # @return [Array] a Rack response triple
      def cli(request)
        result = @handler.handle(nut: request.GET["nut"].to_s, body: form_body(request), ip: client_ip(request))
        [200, { "content-type" => "text/plain; charset=utf-8", "cache-control" => "no-store",
                "x-sqrl-tif" => result.tif.to_hex }, [result.body]]
      rescue Server::RateLimited => e
        rate_limited(e)
      end

      # The 429 response for a {Server::RateLimited} raised by a hook.
      #
      # @return [Array] a Rack response triple
      def rate_limited(error, json: false)
        headers = RATE_LIMITED_HEADERS.dup
        headers["retry-after"] = error.retry_after.to_i.to_s if error.retry_after
        body = json ? JSON.generate(error: "rate_limited", message: error.message) : "#{error.message}\n"
        headers["content-type"] = "application/json; charset=utf-8" if json
        [429, headers, [body]]
      end

      # Hand the page a fresh login URL for its browser session (a new pending login and
      # nut, carrying over +return_to+ and the link target of the previous one), as JSON:
      # +{"sqrl_url", "status_url", "qr_svg"}+. +qr=0+ leaves the QR code out.
      #
      # @return [Array] a Rack response triple
      def refresh(request)
        previous_id = pending_login_id(request)
        previous = previous_id && @handler.stores.pending_logins.find(previous_id)
        login = issue(request, return_to: previous&.return_to, link_user_ref: previous&.link_user_ref)
        payload = { sqrl_url: login.url, status_url: status_url(request), refresh_url: refresh_url(request) }
        payload[:qr_svg] = QR.svg(login.url) unless request.GET["qr"] == "0"
        [200, { "content-type" => "application/json; charset=utf-8", "cache-control" => "no-store" },
         [JSON.generate(payload)]]
      rescue Server::RateLimited => e
        rate_limited(e, json: true)
      end

      # Answer the browser's poll with JSON.
      #
      # @return [Array] a Rack response triple
      def status(request)
        id = pending_login_id(request)
        payload =
          if id.nil?
            { authenticated: false }
          else
            login = @handler.stores.pending_logins.find(id)
            if login.nil? || login.expired?(@config.now)
              { authenticated: false, expired: true }
            elsif login.authenticated? && poll_completable?(login)
              { authenticated: true, next: callback_url(request) }
            else
              { authenticated: false }
            end
          end
        [200, { "content-type" => "application/json; charset=utf-8", "cache-control" => "no-store" },
         [JSON.generate(payload)]]
      end

      # Complete a login. With a +t=+ token (CPS) the token is claimed once and must
      # belong to this browser's pending login; without one, the browser's own pending
      # login is completed if the SQRL client authenticated it. Either way the pending
      # login is detached from the session so it completes at most once. On success the
      # identity's +idk+ is stored under +identity_key+.
      #
      # @return [Completion, nil]
      def callback(request)
        session = session_of(request)
        token = request.GET["t"]
        expected_id = session[@session_key]
        login, via =
          if token && !token.empty?
            [@handler.claim_cps(token), :cps]
          else
            [expected_id && @handler.stores.pending_logins.find(expected_id), :poll]
          end
        return nil if login.nil? || expected_id.nil? || !Util.secure_compare(login.id.to_s, expected_id.to_s)
        return nil unless login.authenticated? && !login.expired?(@config.now)
        return nil if via == :poll && !poll_completable?(login)

        identity = @handler.stores.identities.find(login.authenticated_idk)
        return nil if identity.nil? || identity.disabled?

        session.delete(@session_key)
        session[@identity_key] = identity.idk_b64
        Completion.new(identity: identity, pending_login: login, via: via)
      end

      # Whether a pending login may be completed without a CPS token.
      def poll_completable?(login)
        !@poll_requires_ip_match || login.ip_matched == true
      end

      # The identity currently logged in through SQRL in this browser session, or nil.
      def current_identity(request)
        session = request.env["rack.session"]
        idk_b64 = session && session[@identity_key]
        return nil unless idk_b64

        @handler.stores.identities.find(Util.b64u_decode(idk_b64.to_s))
      rescue FormatError
        nil
      end

      # Forget the SQRL login and any pending login in this browser session.
      def logout(request)
        session = request.env["rack.session"]
        return unless session

        session.delete(@identity_key)
        session.delete(@session_key)
        nil
      end

      # Serve +sqrl.js+.
      #
      # @return [Array] a Rack response triple
      def script(request)
        etag = %("#{Assets.javascript_digest}")
        if request.env["HTTP_IF_NONE_MATCH"] == etag
          return [304, { "etag" => etag, "cache-control" => "public, max-age=86400" }, []]
        end

        [200, { "content-type" => "application/javascript; charset=utf-8", "etag" => etag,
                "cache-control" => "public, max-age=86400" }, [Assets.javascript]]
      end

      # Browser-facing URLs, honouring the mount prefix (+SCRIPT_NAME+).
      def status_url(request) = prefixed(request, @status_path)
      # @return [String] path of the callback for this request (mount prefix included)
      def callback_url(request) = prefixed(request, @callback_path)
      # @return [String] path of +sqrl.js+ for this request (mount prefix included)
      def script_url(request) = prefixed(request, @script_path)
      # @return [String] path of the refresh endpoint for this request (mount prefix included)
      def refresh_url(request) = prefixed(request, @refresh_path)

      # The client IP a request comes from.
      def client_ip(request)
        (@ip ? @ip.call(request) : request.ip).to_s
      end

      private

      # The POST body. Middleware upstream (Rack::Protection, parameter parsers) may
      # already have consumed +rack.input+ without rewinding it, so a form body is rebuilt
      # from Rack's cached form hash; SQRL values are base64url, which the form decoding
      # leaves untouched.
      def form_body(request)
        if request.form_data? && request.POST.any?
          request.POST.map { |k, v| "#{k}=#{v}" }.join("&")
        else
          body = request.body
          body.rewind if body.respond_to?(:rewind)
          data = body.read.to_s
          body.rewind if body.respond_to?(:rewind)
          data
        end
      rescue StandardError
        ""
      end

      def prefixed(request, path)
        "#{request.script_name}#{path}"
      end

      def session_of(request)
        session = request.env["rack.session"]
        return session if session

        raise Error, "SQRL::Rack needs a session: add a session middleware (for example " \
                     "Rack::Session::Cookie) before SQRL::Rack::Middleware, or `enable :sessions` in Sinatra"
      end
    end
  end
end
