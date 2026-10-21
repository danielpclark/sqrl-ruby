# frozen_string_literal: true

require_relative "server/stores"
require_relative "server/memory"
require_relative "server/config"

module SQRL
  # The server side of the SQRL protocol.
  #
  # {Handler} is a pure function of (nut, form body, client IP, stores, config): it knows
  # nothing about HTTP. Framework integrations route the SQRL endpoint's POST body to
  # {Handler#handle}, render {Handler#new_login_url} on the login page, answer the browser's
  # poll from {Handler#status} and complete a CPS login through {Handler#claim_cps}.
  module Server
    # Raised by a +before_issue+ / +before_handle+ hook to refuse a request (rate limit,
    # block list). HTTP integrations answer 429.
    class RateLimited < SQRL::Error
      # Seconds the client should wait, or nil.
      attr_reader :retry_after

      def initialize(message = "too many SQRL requests", retry_after: nil)
        super(message)
        @retry_after = retry_after
      end
    end

    # A freshly issued login URL.
    LoginURL = Struct.new(:url, :nut, :pending_login_id, :cancel_url, keyword_init: true) do
      # The URL base64url-encoded, as the +localhost:25519/<b64>+ CPS link form carries it.
      def b64 = Util.b64u_encode(url.b)
      alias_method :to_s, :url
    end

    # Outcome of one request to the SQRL endpoint.
    Result = Struct.new(:body, :tif, :command, :idk, :pending_login_id, :pending_login, :authenticated, :created,
                        :rekeyed_from, :identity, :cps_url, keyword_init: true) do
      def authenticated? = authenticated ? true : false
      def created? = created ? true : false
      def rekeyed? = !rekeyed_from.nil?
      # @return [String, nil] the identity key as base64url
      def idk_b64 = idk && Util.b64u_encode(idk)

      # @return [String] a short description with secret material redacted
      def inspect
        "#<SQRL::Server::Result #{command || "?"} tif=0x#{tif.to_hex} authenticated=#{authenticated?}>"
      end
    end

    # Server-side protocol handler. Port of the reference server, with its state behind
    # the {Stores} interfaces and a one-time CPS token for the callback.
    class Handler
      attr_reader :config, :stores

      # @param config [Config]
      # @param stores [Stores]
      def initialize(config:, stores: Memory.stores)
        raise ArgumentError, "config must be a SQRL::Server::Config" unless config.is_a?(Config)

        @config = config
        @stores = stores
        @counter = 0
        @counter_mutex = Mutex.new
      end

      # Issue a fresh +sqrl://+ login URL for a browser's login page.
      #
      # @param pending_login_id [String, nil] id to keep in the browser session; generated
      #   when nil
      # @param ip [String] the browser's IP
      # @param cancel_url [String, nil] URL (or site path) encoded into +can=+
      # @param return_to [String, nil] where to send the browser after login (stored on
      #   the pending login for the framework)
      # @param link_user_ref [Object, nil] the signed-in user to link a new identity to
      # @return [LoginURL]
      def new_login_url(pending_login_id = nil, ip:, cancel_url: nil, return_to: nil, link_user_ref: nil)
        now = @config.now
        pending_login_id ||= new_id
        @config.before_issue&.call({ ip: ip.to_s, pending_login_id: pending_login_id, config: @config })
        count_request
        nut = new_nut
        url = "#{@config.scheme}://#{@config.host}#{@config.path}?"
        url << "x=#{@config.path_extension}&" if @config.path_extension
        url << "nut=#{nut}"
        url << "&can=#{Util.b64u_encode(cancel_url.b)}" if cancel_url
        @stores.pending_logins.create(pending_login_id, ip: ip, return_to: return_to, link_user_ref: link_user_ref,
                                                        expires_at: now + @config.nut_ttl, created_at: now)
        @stores.nuts.issue(nut: nut, pending_login_id: pending_login_id, expected_server: Util.b64u_encode(url.b),
                           ip: ip, bound_idk: nil, expires_at: now + @config.nut_ttl)
        LoginURL.new(url: url.freeze, nut: nut, pending_login_id: pending_login_id, cancel_url: cancel_url)
      end

      # State of a pending login, for the browser's poll.
      #
      # @return [Hash] +{ authenticated: Boolean, idk: String (base64url) or nil }+
      def status(pending_login_id)
        login = pending_login_id && @stores.pending_logins.find(pending_login_id)
        return { authenticated: false, idk: nil } if login.nil? || login.expired?(@config.now)
        # A login the client flagged cps is completed only through the url= token the client
        # hands its own browser: "the web server ... MUST NOT authenticate the browser session
        # upon successful authentication" (On The Wire v1.07 p.14; Operating Details p.4).
        return { authenticated: false, idk: nil } if login.cps?

        { authenticated: login.authenticated?,
          idk: login.authenticated_idk && Util.b64u_encode(login.authenticated_idk) }
      end

      # Claim a one-time CPS token from the callback URL.
      #
      # @return [PendingLogin, nil] nil when unknown, already used or expired
      def claim_cps(token)
        return nil if token.nil? || token.to_s.empty?

        @stores.pending_logins.claim_cps_token(token.to_s, now: @config.now)
      end

      # Handle a POST to the SQRL endpoint.
      #
      # @param nut [String] the +nut=+ from the request URL's query string
      # @param body [String] the form body
      # @param ip [String] the client's address
      # @return [Result] whose +body+ is the response (base64url text)
      def handle(nut:, body:, ip:)
        @config.before_handle&.call({ phase: :request, ip: ip.to_s, nut: nut.to_s, command: nil, idk: nil,
                                      config: @config })
        count_request
        tx = Transaction.new(self, nut: nut.to_s, body: body.to_s, ip: ip.to_s)
        tx.run
      end

      # Count one request and prune opportunistically every +config.prune_every+ requests.
      # @api private
      def count_request
        every = @config.prune_every
        return unless every

        due = @counter_mutex.synchronize do
          @counter += 1
          (@counter % every).zero?
        end
        prune! if due
      end

      # Delete expired nuts and pending logins.
      def prune!
        now = @config.now
        @stores.nuts.prune!(now)
        @stores.pending_logins.prune!(now)
        nil
      end

      # A fresh, unpredictable nut (12 random bytes plus a counter).
      # @api private
      def new_nut
        Util.b64u_encode(Util.random_bytes(12))
      end

      # A fresh pending-login id (random, base64url).
      # @api private
      def new_id
        Util.b64u_encode(Util.random_bytes(18))
      end

      # A fresh one-time CPS token (32 random bytes, base64url).
      # @api private
      def new_token
        Util.b64u_encode(Util.random_bytes(32))
      end

      # Parse an +application/x-www-form-urlencoded+ body. SQRL values are base64url, so
      # percent-decoding is only applied to values that actually contain escapes.
      def self.parse_form(body)
        body.to_s.strip.split("&").reject(&:empty?).map do |kv|
          k, v = kv.split("=", 2)
          [k, URL.percent_decode(v || "")]
        end
      end

      # One request's worth of state. @api private
      class Transaction
        def initialize(handler, nut:, body:, ip:)
          @handler = handler
          @config = handler.config
          @stores = handler.stores
          @nut = nut
          @body = body
          @ip = ip
          @now = @config.now
          @tif = 0
          @extra = []
          @sin = nil
          @result = Result.new(authenticated: false, created: false)
        end

        # Execute the transaction: nut lookup, verification, command, response.
        # @return [Result]
        def run
          record = @stores.nuts.consume(@nut, now: @now)
          return transient_error unless record

          @record = record
          # Carry the identity binding from the start so that a malformed request cannot
          # hand out an unbound nut for a transaction that already bound an identity.
          @bound = record.bound_idk
          @login_id = record.pending_login_id
          @login = @stores.pending_logins.find(@login_id)
          return transient_error if @login.nil? || @login.expired?(@now)

          @result.pending_login_id = @login_id
          @sin = @config.sin_for(context)

          form = Handler.parse_form(@body)
          get = ->(k) { form.find { |(n, _)| n == k }&.last }
          client_b64 = get.call("client")
          server_b64 = get.call("server")
          ids_b64 = get.call("ids")
          return fail_with(Tif::CLIENT_FAILURE | Tif::COMMAND_FAILED) unless client_b64 && server_b64 && ids_b64
          return fail_with(Tif::CLIENT_FAILURE | Tif::COMMAND_FAILED) unless Util.secure_compare(server_b64,
                                                                                                 record.expected_server)

          client_text = decode_client(client_b64)
          return fail_with(Tif::CLIENT_FAILURE | Tif::COMMAND_FAILED) unless client_text

          params = Protocol.parse_pairs(client_text)
          cget = ->(k) { params.find { |(n, _)| n == k }&.last }

          ver_ok = Protocol.version_supported?(cget.call("ver"), Protocol::VERSION)
          cmd = Command.parse(cget.call("cmd"))
          idk = decode32(cget.call("idk"))
          return fail_with(Tif::CLIENT_FAILURE | Tif::COMMAND_FAILED) unless ver_ok && idk
          return fail_with(Tif::FUNCTION_NOT_SUPPORTED | Tif::COMMAND_FAILED) unless cmd

          @result.command = cmd
          @result.idk = idk
          @config.before_handle&.call({ phase: :command, ip: @ip, nut: @nut, command: cmd, idk: idk, config: @config })

          # --- signature verification ---
          signed = (client_b64 + server_b64).b
          ids = decode64(ids_b64)
          sig_ok = ids && Crypto.ed25519_verify(idk, signed, ids)
          pidk = decode32(cget.call("pidk"))
          pids_b64 = get.call("pids")
          pids_ok =
            if pidk && pids_b64
              (pids = decode64(pids_b64)) && Crypto.ed25519_verify(pidk, signed, pids)
            else
              pidk.nil? && pids_b64.nil?
            end
          return fail_with(Tif::CLIENT_FAILURE | Tif::COMMAND_FAILED) unless sig_ok && pids_ok

          # --- identity binding to the session ---
          if @bound && !Util.secure_compare(@bound, idk)
            return fail_with(Tif::BAD_ID_ASSOCIATION | Tif::COMMAND_FAILED)
          end

          @bound = idk
          opts = ClientOptions.from_wire(cget.call("opt"))
          if record.ip == @ip
            @tif |= Tif::IPS_MATCHED
          elsif !opts.noiptest? && @config.require_ip_match?
            return fail_with(Tif::COMMAND_FAILED)
          end

          if @stores.identities.superseded?(idk)
            # "the server must immediately fail that client query by returning a TIF of 0x240"
            @tif = 0
            return fail_with(Tif::IDENTITY_SUPERSEDED | Tif::COMMAND_FAILED)
          end

          # --- which identity does the server know? ---
          current = @stores.identities.find(idk)
          previous = pidk && !current ? @stores.identities.find(pidk) : nil
          id_match = !current.nil?
          prev_match = !previous.nil?
          @tif |= Tif::ID_MATCH if id_match
          @tif |= Tif::PREVIOUS_ID_MATCH if prev_match
          matched = current || previous
          @tif |= Tif::SQRL_DISABLED if matched&.disabled?
          @result.identity = matched

          # ask / btn bookkeeping
          btn = cget.call("btn")&.then { |b| b.match?(/\A\d+\z/) ? b.to_i : nil }
          updates = { last_command: cmd }
          updates[:btn] = btn if btn
          @login = @stores.pending_logins.update(@login_id, **updates)
          ask = @config.ask_for(context(identity: matched, idk: idk))
          ask_pending = !ask.nil? && @login.btn.nil?
          # Answered with a button the site does not accept (for example "Deny"): the
          # transaction cannot authenticate until the client answers again.
          ask_refused = !ask.nil? && !@login.btn.nil? && !ask.accepts?(@login.btn)

          suk_new = decode32(cget.call("suk"))
          vuk_new = decode32(cget.call("vuk"))
          urs = get.call("urs")&.then { |u| decode64(u) }
          urs_ok = ->(vuk) { !urs.nil? && Crypto.ed25519_verify(vuk, signed, urs) }

          # --- re-key: previous identity matched and the new keys were supplied ---
          rekey_failed = false
          if prev_match && cmd != Command::QUERY
            ins_ok = @sin.nil? || previous.ins.nil? || Util.secure_compare(previous.ins, cget.call("pins").to_s)
            if suk_new && vuk_new && urs_ok.call(previous.vuk) && ins_ok
              current = @stores.identities.rekey(pidk, idk, suk: suk_new, vuk: vuk_new, ins: cget.call("ins"))
              # The urs under the previous identity's VUK carries the same (rescue code) authority
              # as an enable, so a disabled account comes back enabled under its new key, "so that
              # the account can be immediately used under the new key" (Gibson, grc.sqrl:20273).
              current = @stores.identities.update(idk, disabled: false) if current.disabled?
              @result.rekeyed_from = pidk
              @result.identity = current
              id_match = true
              # TIF bits describe the account AFTER the update: current-ID match on, previous-ID
              # match off (On The Wire v1.07 p.16-17; Gibson, grc.sqrl:22934).
              @tif |= Tif::ID_MATCH
              @tif &= ~(Tif::PREVIOUS_ID_MATCH | Tif::SQRL_DISABLED)
            else
              rekey_failed = true
            end
          end

          case cmd
          when Command::QUERY
            # An ask is only valid in a query reply that recognises the current identity.
            if ask_pending && id_match
              @extra << ["ask", ask.to_wire]
              @login = @stores.pending_logins.update(@login_id, asked: true)
            end
          when Command::IDENT
            if rekey_failed || (ask_pending && @login.asked?) || ask_refused
              @tif |= Tif::COMMAND_FAILED
            elsif id_match
              if current.disabled?
                @tif |= Tif::COMMAND_FAILED
              else
                attrs = { sqrlonly: opts.sqrlonly?, hardlock: opts.hardlock? }
                if @sin
                  ins = cget.call("ins")
                  return fail_with(Tif::COMMAND_FAILED) unless ins && (current.ins.nil? || Util.secure_compare(
                    current.ins, ins
                  ))

                  attrs[:ins] = ins
                end
                attrs[:logins] = current.logins.to_i + 1
                attrs[:user_ref] = @login.link_user_ref if current.user_ref.nil? && @login.link_user_ref
                current = @stores.identities.update(idk, **attrs)
                authenticate!(current, cmd, opts)
              end
            else
              create_account(idk, suk_new, vuk_new, opts, cget.call("ins"), cmd)
            end
          when Command::DISABLE
            if rekey_failed || !id_match
              @tif |= Tif::COMMAND_FAILED
            else
              current = @stores.identities.update(idk, disabled: true, sqrlonly: opts.sqrlonly?,
                                                       hardlock: opts.hardlock?)
              @result.identity = current
              @tif |= Tif::SQRL_DISABLED
              # "url= must be provided by the server in its response to any command, other than
              # query, when the SQRL client includes opt=cps" (On The Wire v1.07 p.14).
              issue_cps_url if opts.cps?
            end
          when Command::ENABLE
            if rekey_failed || !id_match || ask_refused
              @tif |= Tif::COMMAND_FAILED
            elsif prev_match || urs_ok.call(current.vuk)
              # after a re-key the urs was already verified against the old vuk
              current = @stores.identities.update(idk, disabled: false, logins: current.logins.to_i + 1,
                                                       sqrlonly: opts.sqrlonly?, hardlock: opts.hardlock?)
              @tif &= ~Tif::SQRL_DISABLED
              authenticate!(current, cmd, opts)
            else
              @tif |= Tif::COMMAND_FAILED | Tif::CLIENT_FAILURE
            end
          when Command::REMOVE
            if rekey_failed || !id_match
              @tif |= Tif::COMMAND_FAILED
            elsif prev_match || urs_ok.call(current.vuk)
              @stores.identities.remove(idk)
              @result.identity = nil
              @tif &= ~(Tif::ID_MATCH | Tif::SQRL_DISABLED)
              @login = @stores.pending_logins.update(@login_id, authenticated_idk: nil, authenticated_at: nil)
              issue_cps_url if opts.cps?
            else
              @tif |= Tif::COMMAND_FAILED | Tif::CLIENT_FAILURE
            end
          end

          # The stored SUK goes back whenever the client asked for it with opt=suk (a MUST:
          # Gibson, grc.sqrl:12289, 9 Jan 2016) and whenever the client is likely to need it for
          # a urs: the account is disabled, or it was recognised by a previous identity
          # (On The Wire v1.07 p.14). It accompanies every command's reply, as GRC's server does.
          identity_now = @result.identity
          if identity_now && (opts.suk? || identity_now.disabled? || prev_match)
            @extra << ["suk", Util.b64u_encode(identity_now.suk)]
          end
          respond
        end

        private

        def context(identity: nil, idk: nil)
          { pending_login: @login, pending_login_id: @login_id, ip: @ip, identity: identity, idk: idk,
            config: @config }
        end

        def decode_client(b64)
          text = Util.b64u_decode(b64).force_encoding(Encoding::UTF_8)
          text.valid_encoding? ? text : nil
        rescue FormatError
          nil
        end

        def decode32(b64)
          b64 && Util.b64u_decode_fixed(b64, 32)
        rescue FormatError
          nil
        end

        def decode64(b64)
          b64 && Util.b64u_decode_fixed(b64, 64)
        rescue FormatError
          nil
        end

        def create_account(idk, suk, vuk, opts, ins, cmd)
          unless suk && vuk
            @tif |= Tif::COMMAND_FAILED | Tif::CLIENT_FAILURE
            return
          end
          user_ref = @login.link_user_ref
          case @config.on_unknown_identity
          when :refuse
            @tif |= Tif::COMMAND_FAILED
            return
          when :link
            if user_ref.nil?
              @tif |= Tif::COMMAND_FAILED
              return
            end
          end
          identity = @stores.identities.create(idk: idk, suk: suk, vuk: vuk, disabled: false,
                                               sqrlonly: opts.sqrlonly?, hardlock: opts.hardlock?,
                                               ins: ins, logins: 1, user_ref: user_ref)
          @tif |= Tif::ID_MATCH
          @result.created = true
          authenticate!(identity, cmd, opts)
        end

        def authenticate!(identity, cmd, opts)
          @result.identity = identity
          @result.authenticated = true
          @login = @stores.pending_logins.update(@login_id, authenticated_idk: identity.idk, authenticated_at: @now,
                                                            ip_matched: @tif.anybits?(Tif::IPS_MATCHED))
          issue_cps_url if opts.cps?
          @config.on_authenticated&.call(identity, @login, cmd)
        end

        def issue_cps_url
          token = @handler.new_token
          @login = @stores.pending_logins.update(@login_id, cps_token: token,
                                                            cps_token_expires_at: @now + @config.cps_token_ttl)
          url = @config.cps_url_for(token, @login)
          @result.cps_url = url
          @extra << ["url", url]
        end

        # Unknown, expired or reused nut: transient error. This server keeps its state "by
        # reference" (On The Wire, "Transient Error Details", second case), so the browser
        # session behind a stale nut cannot be recovered. The reply carries a fresh nut, as every
        # reply must, but that nut is deliberately not registered: the client's retry fails with
        # the identical TIF, which is the client's cue to tell its user to refresh the login page
        # (Gibson, grc.sqrl:23543, 23 Nov 2019; On The Wire v1.07 p.17).
        def transient_error
          @tif |= Tif::TRANSIENT_ERROR | Tif::COMMAND_FAILED
          @login_id = nil
          @login = nil
          @bound = nil
          @sin = @config.sin_for(context)
          respond(register_nut: false)
        end

        def fail_with(bits)
          @tif |= bits
          respond
        end

        def respond(register_nut: true)
          nut = @handler.new_nut
          text = "ver=#{Protocol::VERSION}\r\nnut=#{nut}\r\ntif=#{Tif.new(@tif).to_hex}\r\nqry=#{@config.path}?nut=#{nut}\r\n"
          text << "sin=#{@sin}\r\n" if @sin
          @extra.each { |k, v| text << "#{k}=#{v}\r\n" }
          body = Util.b64u_encode(text.b)
          if register_nut
            @stores.nuts.issue(nut: nut, pending_login_id: @login_id, expected_server: body,
                               ip: @record ? @record.ip : @ip, bound_idk: @bound, expires_at: @now + @config.nut_ttl)
          end
          @result.body = body
          @result.tif = Tif.new(@tif)
          @result.pending_login = @login
          log
          @result
        end

        def log
          logger = @config.logger
          return unless logger.respond_to?(:debug)

          logger.debug("[sqrl] #{@result.command || "invalid"} tif=0x#{@result.tif.to_hex} " \
                       "login=#{@login_id} authenticated=#{@result.authenticated?}")
        end
      end
    end
  end
end
