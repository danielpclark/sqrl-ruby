# frozen_string_literal: true

require "json"

module SQRL
  module Client
    # The outcome of one {Agent} operation.
    class LoginResult
      # @return [Symbol] +:query+, +:ident+, +:disable+, +:enable+ or +:remove+
      attr_reader :command
      # @return [String] the +sqrl://+ URL that was used
      attr_reader :sqrl_url
      # @return [SQRL::Session::State] state after the last exchange
      attr_reader :state
      # @return [SQRL::Tif, nil] TIF of the last response
      attr_reader :tif
      # @return [Array<SQRL::Tif>] every TIF received, in order
      attr_reader :tif_history
      # @return [String] the identity's per-site public key, base64url
      attr_reader :idk
      # @return [String, nil] the validated CPS +url=+ when the server sent one
      attr_reader :cps_url
      # @return [Transport::Response, nil] the response of following the CPS URL
      attr_reader :landing
      # @return [Hash, nil] the last JSON answer of the status poll (non-CPS logins)
      attr_reader :status
      # @return [HTTP::CookieJar] the cookies, including those set by the landing page
      attr_reader :cookies
      # @return [Array<Hash>] one entry per wire exchange (signatures are not recorded)
      attr_reader :transcript
      # @return [SQRL::Ask, nil] the question the server posed, if any
      attr_reader :ask
      # @return [Integer, nil] the button that answered it
      attr_reader :button
      # @return [String, nil] the cancel URL offered by the site
      attr_reader :cancel_url

      # @api private
      def initialize(command:, sqrl_url:, state:, tif:, tif_history:, idk:, cookies:, transcript:, created: false,
                     rekeyed: false, authenticated: false, cps_url: nil, landing: nil, status: nil, ask: nil,
                     button: nil, cancel_url: nil)
        @command = command
        @sqrl_url = sqrl_url
        @state = state
        @tif = tif
        @tif_history = tif_history
        @idk = idk
        @cookies = cookies
        @transcript = transcript
        @created = created
        @rekeyed = rekeyed
        @authenticated = authenticated
        @cps_url = cps_url
        @landing = landing
        @status = status
        @ask = ask
        @button = button
        @cancel_url = cancel_url
      end

      # Whether the site accepted the login (or enable) and the session is established.
      def authenticated? = @authenticated
      # Whether this operation created the account on the site.
      def created? = @created
      # Whether this operation moved the site's account to a re-keyed identity.
      def rekeyed? = @rekeyed
      # Whether the site knows the identity (after a +query+).
      def known? = state.known?
      def disabled? = state.disabled?

      def to_h
        { command: command, sqrl_url: sqrl_url, state: state.kind, disabled: state.disabled?, tif: tif&.to_hex,
          idk: idk, authenticated: authenticated?, created: created?, rekeyed: rekeyed?, cps_url: cps_url,
          landing_status: landing&.status, landing_url: landing&.final_url, ask: ask&.message, button: button }
      end

      def inspect
        "#<SQRL::Client::LoginResult #{command} #{state.kind} authenticated=#{authenticated?}>"
      end
    end

    # A headless SQRL client that performs whole transactions against a site: discovery of
    # the login link, the +query+ → +ident+ dance (including account creation, re-keying,
    # previous identities, +ask+ answers and +sin+/+ins+), the CPS handoff, and the account
    # commands +disable+, +enable+ and +remove+.
    class Agent
      # Seconds between status polls for non-CPS logins.
      DEFAULT_POLL_INTERVAL = 0.5

      attr_reader :identity, :transport, :options, :alt_id, :logger
      attr_accessor :cps, :follow_cps, :unknown_site, :ask_handler, :max_transient_retries, :poll, :poll_interval,
                    :poll_timeout

      # @param identity [Identity]
      # @param transport [#get, #post_form] defaults to a fresh {Transport}
      # @param cps [Boolean] request a Client Provided Session (+url=+)
      # @param follow_cps [Boolean] GET the CPS +url=+ with the agent's own cookie jar; set
      #   to false when something else (a browser) will visit it, since the token is one-time
      # @param unknown_site [Symbol] +:create+ an account on sites that do not know the
      #   identity, or +:refuse+ to
      # @param options [Hash] +sqrlonly:+, +hardlock:+, +noiptest:+
      # @param alt_id [String, nil] SQRL Alt-ID (a different identity on the same site)
      # @param ask_handler [#call, nil] receives the {SQRL::Ask} and returns the button
      #   number (0 for the plain OK, 1 or 2); without one an +ask+ raises {AskRequired}
      # @param max_transient_retries [Integer]
      # @param poll [Boolean] for non-CPS logins, poll the site's status URL when one was
      #   discovered
      # @param poll_timeout [Numeric] seconds
      # +insecure: true+ accepts the loopback-only +qrl://+ (plain http) testing mode and
      # lets the default transport speak plain http to loopback hosts. Off by default:
      # SQRL is +sqrl://+ over HTTPS.
      def initialize(identity:, transport: nil, cps: true, follow_cps: true, unknown_site: :create, options: {},
                     alt_id: nil, ask_handler: nil, max_transient_retries: 2, poll: true,
                     poll_interval: DEFAULT_POLL_INTERVAL, poll_timeout: 10, logger: nil, insecure: false)
        raise ArgumentError, "unknown_site must be :create or :refuse" unless %i[create refuse].include?(unknown_site)

        @identity = identity
        @insecure = insecure ? true : false
        @transport = transport || Transport.new(logger: logger, allow_http: @insecure ? :loopback : false)
        @cps = cps
        @follow_cps = follow_cps
        @unknown_site = unknown_site
        @options = { sqrlonly: false, hardlock: false, noiptest: false }.merge(options)
        @alt_id = alt_id
        @ask_handler = ask_handler
        @max_transient_retries = max_transient_retries
        @poll = poll
        @poll_interval = poll_interval
        @poll_timeout = poll_timeout
        @logger = logger
      end

      # The transport, for the bot's own requests after logging in.
      alias http transport

      # Whether plain-http / +qrl://+ loopback testing mode is on.
      def insecure? = @insecure

      # Log in (creating the account, or re-keying it, as the site's answer dictates).
      #
      # @param target [String] a login page URL, a +sqrl://+ URL or a
      #   +localhost:25519/<b64>+ CPS link
      # @return [LoginResult]
      # @raise [LoginFailed, AskRequired, DiscoveryError, TransportError]
      def login(target)
        run(target, :ident)
      end

      # Ask the site whether it knows the identity, without logging in.
      def query(target)
        run(target, :query)
      end

      # Disable SQRL login for the account on the site.
      def disable(target)
        run(target, :disable)
      end

      # Re-enable SQRL login. Needs the IUK (ephemeral/created identities have it; file
      # identities take +rescue_code:+).
      def enable(target, rescue_code: nil)
        run(target, :enable, rescue_code: rescue_code)
      end

      # Remove the SQRL association from the account. Needs the IUK like {#enable}.
      def remove(target, rescue_code: nil)
        run(target, :remove, rescue_code: rescue_code)
      end

      # Discover the login link for +target+ without talking SQRL.
      #
      # @return [Discovery::Result]
      def discover(target)
        direct = Discovery.from_target(target)
        return direct if direct

        page = @transport.get(target)
        unless page.success?
          raise TransportError.new("login page #{target} answered #{page.status}", url: target, status: page.status)
        end

        Discovery.find(page.body, base_url: page.final_url)
      end

      private

      def client_options
        ClientOptions.new(cps: @cps, sqrlonly: @options[:sqrlonly], hardlock: @options[:hardlock],
                          noiptest: @options[:noiptest])
      end

      def run(target, command, rescue_code: nil)
        found = discover(target)
        session = Session.new(@identity.unlocked, found.sqrl_url, options: client_options, alt_id: @alt_id,
                                                                  insecure: @insecure)
        ctx = Context.new(found, session)
        transient = 0

        loop do
          query_until_settled(ctx)
          break if command == :query

          ctx.pre_state = session.state
          answer_ask(ctx)
          request = build_command(ctx, command, rescue_code)
          exchange(ctx, request)
          break unless session.state.transient?

          transient += 1
          next unless transient > @max_transient_retries

          raise LoginFailed.new("the server kept answering with a transient error", reason: :transient,
                                                                                    tif: session.last_response.tif,
                                                                                    state: session.state)
        end

        finish(ctx, command)
      end

      # Small bag of per-transaction state. @api private
      Context = Struct.new(:found, :session, :pre_state, :tifs, :transcript, :ask, :button, :landing, :status) do
        def initialize(found, session)
          super(found, session, nil, [], [], nil, nil, nil, nil)
        end
      end

      # Query until the server has classified the identity, retrying on transient errors
      # and walking the previous identities when the current one is unknown.
      def query_until_settled(ctx)
        session = ctx.session
        transient = 0
        loop do
          exchange(ctx, session.query)
          state = session.state
          case state.kind
          when :transient
            transient += 1
            next if transient <= @max_transient_retries

            raise LoginFailed.new("the server kept answering with a transient error", reason: :transient,
                                                                                      tif: session.last_response.tif, state: state)
          when :unknown
            next if session.has_previous? && session.try_next_previous

            return
          when :known, :previous_known
            return
          when :superseded
            raise LoginFailed.new("this identity was superseded on the site by a newer one", reason: :superseded,
                                                                                             tif: session.last_response.tif, state: state)
          else
            reason = session.ip_check_failed? ? :ip_mismatch : :failed
            raise LoginFailed.new(state.message || "query failed", reason: reason, tif: session.last_response.tif,
                                                                   state: state)
          end
        end
      end

      def answer_ask(ctx)
        ask = ctx.session.pending_ask
        return unless ask

        ctx.ask = ask
        raise AskRequired, ask unless @ask_handler

        btn = @ask_handler.call(ask).to_i
        ctx.button = btn
        ctx.session.set_button(btn)
      end

      def build_command(ctx, command, rescue_code)
        session = ctx.session
        state = session.state
        case command
        when :ident
          if state.unknown? && @unknown_site == :refuse
            raise LoginFailed.new("#{session.url.host} does not know this identity and unknown_site is :refuse",
                                  reason: :unknown_site, tif: session.last_response.tif, state: state)
          end
          if state.disabled?
            raise LoginFailed.new("SQRL login is disabled for this account on #{session.url.host}", reason: :disabled,
                                                                                                    tif: session.last_response.tif, state: state)
          end
          session.ident
        when :disable
          session.disable
        when :enable, :remove
          iuk = state.previous_known? ? nil : unlock_key(rescue_code)
          command == :enable ? session.enable(iuk) : session.remove(iuk)
        else
          raise ArgumentError, "unknown command #{command.inspect}"
        end
      end

      def unlock_key(rescue_code)
        return @identity.iuk if @identity.iuk?
        return @identity.unlock_iuk!(rescue_code) if rescue_code

        raise IdentityLocked,
              "enable/remove need the Identity Unlock Key: pass rescue_code: or use an identity that has it"
      end

      def exchange(ctx, request)
        response = @transport.post_form(request.url, request.body, { "Accept" => "text/plain" })
        unless response.success?
          raise TransportError.new("SQRL endpoint #{request.url} answered HTTP #{response.status}", url: request.url,
                                                                                                    status: response.status)
        end

        parsed = ctx.session.feed(response.body.strip)
        ctx.tifs << parsed.tif
        ctx.transcript << { command: request.command, url: request.url, client_text: request.client_text,
                            http_status: response.status, tif: parsed.tif.to_hex, response: parsed.params.to_h }
        @logger&.debug { "[sqrl-client] #{request.command} -> tif=0x#{parsed.tif.to_hex} (#{ctx.session.state.kind})" }
        parsed
      end

      def finish(ctx, command)
        session = ctx.session
        state = session.state
        tif = session.last_response&.tif
        authenticated = false
        created = false
        rekeyed = false
        cps_url = nil

        case command
        when :ident, :enable
          unless !tif.error? && tif.id_match? && !(command == :ident && tif.sqrl_disabled?)
            raise LoginFailed.new("#{command} failed: #{state.message || state.kind}", reason: failure_reason(session),
                                                                                       tif: tif, state: state)
          end
          authenticated = true
          created = command == :ident && ctx.pre_state&.unknown?
          rekeyed = ctx.pre_state&.previous_known? || false
        when :disable
          unless !tif.error? && tif.sqrl_disabled?
            raise LoginFailed.new("disable failed: #{state.message || state.kind}", reason: failure_reason(session),
                                                                                    tif: tif, state: state)
          end
        when :remove
          if tif.error? || tif.id_match?
            raise LoginFailed.new("remove failed: #{state.message || state.kind}", reason: failure_reason(session),
                                                                                   tif: tif, state: state)
          end
        end

        if command != :query
          cps_url = session.cps_url
          if authenticated
            if cps_url
              ctx.landing = @transport.get(cps_url) if @follow_cps
            elsif @poll && ctx.found.status_url
              ctx.status = poll_status(ctx)
            end
          end
        end

        LoginResult.new(command: command, sqrl_url: ctx.found.sqrl_url, state: state, tif: tif, tif_history: ctx.tifs,
                        idk: session.idk_b64, cookies: @transport.respond_to?(:cookies) ? @transport.cookies : nil,
                        transcript: ctx.transcript, created: created, rekeyed: rekeyed, authenticated: authenticated,
                        cps_url: cps_url, landing: ctx.landing, status: ctx.status, ask: ctx.ask, button: ctx.button,
                        cancel_url: session.cancel_url)
      end

      def failure_reason(session)
        tif = session.last_response&.tif
        return :unknown if tif.nil?
        return :superseded if tif.identity_superseded?
        return :disabled if tif.sqrl_disabled?
        return :ip_mismatch if session.ip_check_failed?
        return :client_failure if tif.client_failure?
        return :not_supported if tif.function_not_supported?

        :command_failed
      end

      # Poll the discovered status URL until it reports the login, following its +next+
      # URL (which completes a cookie-based login) when it gives one.
      def poll_status(ctx)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @poll_timeout
        last = nil
        loop do
          response = @transport.get(ctx.found.status_url, { "Accept" => "application/json" })
          last = response.json || {}
          if last["authenticated"]
            ctx.landing = @transport.get(URI.join(ctx.found.status_url, last["next"]).to_s) if last["next"]
            return last
          end
          return last if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

          sleep @poll_interval
        end
      end
    end
  end
end
