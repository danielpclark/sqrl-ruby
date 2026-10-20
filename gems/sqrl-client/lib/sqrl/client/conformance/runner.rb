# frozen_string_literal: true

module SQRL
  module Client
    module Conformance
      # Runs the conformance cases against one site. Every case is self-contained: it
      # creates its own identities and its own account, so cases can run individually
      # (the RSpec shared examples do that) or all together with {#run}.
      class Runner
        # Feature flags with their defaults. Turn a flag off when the site does not
        # support that behaviour, so the corresponding cases are skipped instead of failed.
        DEFAULT_FEATURES = {
          cps: true,            # the server sends url= and the landing page logs the browser in
          poll: true,           # a status URL is discoverable and reports the login
          rekey: true,
          remove: true,
          ask: false,           # the site poses an ask= (needs an ask handler policy of "button 1")
          sin: false,           # the site sends sin=
          alt_id: true,
          negative: true,       # malformed / replayed requests
          cps_single_use: true, # the CPS url= may be used once only
          concurrency: true
        }.freeze

        # Case name => [group, feature it needs (or nil)]
        CASES = {
          create_account: ["happy", nil],
          login_existing: ["happy", nil],
          login_cps_landing: ["happy", :cps],
          login_without_cps_poll: ["happy", :poll],
          disable_then_login_refused: ["account", nil],
          enable_with_iuk: ["account", nil],
          remove_then_recreate: ["account", :remove],
          rekey_moves_account: ["rekey", :rekey],
          superseded_identity_refused: ["rekey", :rekey],
          ask_and_button: ["options", :ask],
          sin_and_ins: ["options", :sin],
          alt_id_is_distinct: ["options", :alt_id],
          nut_replay_rejected: ["negative", :negative],
          unknown_nut_is_transient: ["negative", :negative],
          tampered_client_rejected: ["negative", :negative],
          wrong_server_echo_rejected: ["negative", :negative],
          bad_signature_rejected: ["negative", :negative],
          ident_without_lock_rejected: ["negative", :negative],
          cps_token_single_use: ["negative", :cps_single_use],
          callback_without_token_rejected: ["negative", :cps_single_use],
          undefined_tif_bit_aborts_client: ["negative", :negative],
          transient_recovery: ["robustness", nil],
          concurrent_logins: ["robustness", :concurrency]
        }.freeze

        attr_reader :site, :features, :report

        # @param login_url [String] the site's login page
        # @param identity_factory [#call] returns a fresh {Identity} with a known IUK
        # @param transport_factory [#call, nil] returns a fresh {Transport} ("browser")
        # @param features [Hash] overrides of {DEFAULT_FEATURES}
        # @param site [Site, nil] custom site adapter
        # @param success_matcher [#call, nil] see {Site#initialize}
        # @param ask_button [Integer] button to answer an +ask+ with
        # @param only [Array<Symbol>, nil] run only these cases
        def initialize(login_url:, identity_factory: -> { Identity.ephemeral }, transport_factory: nil, features: {},
                       site: nil, success_matcher: nil, ask_button: 1, only: nil, logger: nil)
          @login_url = login_url
          @identity_factory = identity_factory
          @transport_factory = transport_factory || -> { Transport.new(logger: logger) }
          @features = DEFAULT_FEATURES.merge(features.transform_keys(&:to_sym))
          @site = site || Site.new(login_url: login_url, success_matcher: success_matcher)
          @ask_button = ask_button
          @only = only&.map(&:to_sym)
          @logger = logger
          @report = Report.new(login_url: login_url)
        end

        # Names of the cases {#run} would execute (skips included).
        def case_names
          names = CASES.keys
          names &= @only if @only
          names
        end

        # Run every case.
        #
        # @return [Report]
        def run
          case_names.each { |name| @report << run_case(name) }
          @report.finish!
        end

        # Run one case.
        #
        # @return [Case]
        def run_case(name)
          name = name.to_sym
          group, feature = CASES.fetch(name) { raise ArgumentError, "unknown conformance case #{name}" }
          if feature && !@features[feature]
            return Case.new(name: name, group: group, status: :skipped, message: "feature #{feature} disabled")
          end

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          ctx = CaseContext.new
          begin
            send(:"case_#{name}", ctx)
            Case.new(name: name, group: group, status: :passed, duration: elapsed(started), transcript: ctx.transcript)
          rescue Skip => e
            Case.new(name: name, group: group, status: :skipped, message: e.message, duration: elapsed(started))
          rescue StandardError => e
            @logger&.warn { "[conformance] #{name}: #{e.class}: #{e.message}" }
            Case.new(name: name, group: group, status: :failed, message: "#{e.class}: #{e.message}",
                     duration: elapsed(started), transcript: ctx.transcript, error: e)
          end
        end

        # Raised inside a case to mark it skipped.
        class Skip < StandardError; end

        # Raised inside a case on an unmet expectation.
        class Failure < StandardError; end

        # Per-case scratch state. @api private
        class CaseContext
          attr_accessor :transcript

          def initialize
            @transcript = []
          end
        end

        private

        def elapsed(started)
          Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        end

        def check(condition, message)
          raise Failure, message unless condition
        end

        def skip(message)
          raise Skip, message
        end

        def identity = @identity_factory.call
        def transport = @transport_factory.call

        # Agents answer the site's ask (when the feature is on) with the configured button
        # unless a case supplies its own handler.
        def agent(identity, transport: self.transport, **opts)
          defaults = { ask_handler: (@features[:ask] ? ->(_ask) { @ask_button } : nil) }
          Agent.new(identity: identity, transport: transport, logger: @logger, **defaults.merge(opts))
        end

        def login(identity, ctx, **opts)
          result = agent(identity, **opts).login(@login_url)
          ctx.transcript.concat(result.transcript)
          result
        end

        def expect_login_failure(reason, ctx)
          yield
          raise Failure, "expected the login to fail with #{reason}"
        rescue LoginFailed => e
          ctx.transcript << { error: e.class.name, reason: e.reason, tif: e.tif&.to_hex }
          check(e.reason == reason, "expected failure reason #{reason}, got #{e.reason} (tif 0x#{e.tif&.to_hex})")
          e
        end

        def expect_logged_in(result, what)
          check(result.authenticated?, "#{what}: not authenticated (tif 0x#{result.tif&.to_hex})")
          return unless @features[:cps] && result.cps_url

          check(@site.success?(result.landing), "#{what}: following the CPS url= did not land on a logged-in page " \
                                                "(HTTP #{result.landing&.status} at #{result.landing&.final_url})")
        end

        # ---- happy paths -------------------------------------------------------------

        def case_create_account(ctx)
          result = login(identity, ctx, cps: @features[:cps])
          check(result.created?, "first login should create the account")
          expect_logged_in(result, "account creation")
        end

        def case_login_existing(ctx)
          id = identity
          login(id, ctx, cps: @features[:cps])
          result = login(id, ctx, cps: @features[:cps])
          check(!result.created?, "second login must not create another account")
          check(result.state.known?, "second login should be a known identity")
          expect_logged_in(result, "login")
        end

        def case_login_cps_landing(ctx)
          id = identity
          result = login(id, ctx, cps: true)
          check(!result.cps_url.nil?, "the server sent no url= although cps was requested")
          check(result.cps_url.start_with?("https://", "http://"), "CPS url= is not absolute: #{result.cps_url}")
          check(@site.success?(result.landing), "CPS landing is not a logged-in page (HTTP #{result.landing&.status})")
        end

        def case_login_without_cps_poll(ctx)
          id = identity
          page = @site.login_page(transport)
          skip("the login page exposes no status URL") unless page.status_url
          browser = transport
          page = @site.login_page(browser)
          result = agent(id, transport: browser, cps: false).login(page.sqrl_url)
          ctx.transcript.concat(result.transcript)
          check(result.authenticated?, "ident without cps was not accepted")
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
          status = nil
          loop do
            status = browser.get(page.status_url, { "Accept" => "application/json" }).json || {}
            break if status["authenticated"] || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

            sleep 0.3
          end
          check(status["authenticated"], "status URL never reported the login: #{status.inspect}")
          return unless status["next"]

          landing = browser.get(URI.join(page.status_url, status["next"]).to_s)
          check(@site.success?(landing), "following the poll's next URL did not log the browser in (HTTP #{landing.status})")
        end

        # ---- account commands ------------------------------------------------------------

        def case_disable_then_login_refused(ctx)
          id = identity
          login(id, ctx, cps: false, poll: false)
          d = agent(id).disable(@login_url)
          ctx.transcript.concat(d.transcript)
          check(d.tif.sqrl_disabled?, "disable did not set SQRL_DISABLED")
          q = agent(id).query(@login_url)
          check(q.state.known? && q.state.disabled?, "query after disable should report known + disabled")
          expect_login_failure(:disabled, ctx) { login(id, ctx, cps: false, poll: false) }
        end

        def case_enable_with_iuk(ctx)
          id = identity
          skip("identity factory must produce identities with a known IUK") unless id.iuk?
          login(id, ctx, cps: false, poll: false)
          agent(id).disable(@login_url)
          e = agent(id, cps: @features[:cps]).enable(@login_url)
          ctx.transcript.concat(e.transcript)
          expect_logged_in(e, "enable")
          check(!e.tif.sqrl_disabled?, "enable left SQRL_DISABLED set")
          result = login(id, ctx, cps: false, poll: false)
          check(result.authenticated? && !result.state.disabled?, "login after enable failed")
        end

        def case_remove_then_recreate(ctx)
          id = identity
          skip("identity factory must produce identities with a known IUK") unless id.iuk?
          login(id, ctx, cps: false, poll: false)
          r = agent(id).remove(@login_url)
          ctx.transcript.concat(r.transcript)
          check(!r.tif.id_match?, "remove left ID_MATCH set")
          q = agent(id).query(@login_url)
          check(q.state.unknown?, "identity still known after remove")
          again = login(id, ctx, cps: false, poll: false)
          check(again.created?, "login after remove should create the account again")
        end

        # ---- re-keying ---------------------------------------------------------------------

        def case_rekey_moves_account(ctx)
          id = identity
          skip("identity factory must produce identities with a known IUK") unless id.iuk?
          first = login(id, ctx, cps: false, poll: false)
          id.rekey!
          result = login(id, ctx, cps: @features[:cps])
          check(result.rekeyed?, "login with the re-keyed identity did not re-key the account")
          check(result.idk != first.idk, "idk did not change after re-key")
          expect_logged_in(result, "re-key login")
          later = login(id, ctx, cps: false, poll: false)
          check(later.state.known? && !later.rekeyed?, "the re-keyed identity should now be known directly")
        end

        def case_superseded_identity_refused(ctx)
          id = identity
          skip("identity factory must produce identities with a known IUK") unless id.iuk?
          login(id, ctx, cps: false, poll: false)
          id.rekey!
          login(id, ctx, cps: false, poll: false)
          old = id.previous_identity
          expect_login_failure(:superseded, ctx) { login(old, ctx, cps: false, poll: false) }
        end

        # ---- server options --------------------------------------------------------------

        def case_ask_and_button(ctx)
          id = identity
          login(id, ctx, cps: false, poll: false, ask_handler: ->(_ask) { @ask_button })
          asked = nil
          result = login(id, ctx, cps: false, poll: false, ask_handler: ->(ask) { asked = ask; @ask_button })
          check(!asked.nil?, "the server posed no ask= to a known identity")
          check(!asked.message.to_s.empty?, "ask carried no message")
          check(result.authenticated?, "login with the ask answered was not accepted")
          check(result.transcript.last[:client_text].include?("btn=#{@ask_button}"), "btn= was not sent with ident")
          begin
            login(id, ctx, cps: false, poll: false, ask_handler: nil)
            raise Failure, "login without an ask handler should raise AskRequired"
          rescue AskRequired
            nil
          end
        end

        def case_sin_and_ins(ctx)
          id = identity
          first = login(id, ctx, cps: false, poll: false)
          check(first.transcript.last[:response].key?("sin") || first.transcript.first[:response].key?("sin"),
                "the server sent no sin=")
          check(first.transcript.last[:client_text].include?("ins="), "ins= was not sent")
          second = login(id, ctx, cps: false, poll: false)
          check(second.authenticated?, "second login with ins= failed")
        end

        def case_alt_id_is_distinct(ctx)
          id = identity
          a = login(id, ctx, cps: false, poll: false)
          b = login(id, ctx, cps: false, poll: false, alt_id: "conformance")
          check(a.idk != b.idk, "Alt-ID produced the same idk")
          check(b.created?, "Alt-ID login should create a separate account")
        end

        # ---- negative ----------------------------------------------------------------------

        # A raw session against a fresh login page: [session, transport, page].
        def raw_session(id, options: ClientOptions.new)
          browser = transport
          page = @site.login_page(browser)
          [Session.new(id.unlocked, page.sqrl_url, options: options), browser, page]
        end

        def raw_post(browser, url, body, ctx, label)
          response = browser.post_form(url, body, { "Accept" => "text/plain" })
          check(response.success?, "#{label}: SQRL endpoint answered HTTP #{response.status}")
          parsed = ServerResponse.parse(response.body.strip)
          ctx.transcript << { label: label, tif: parsed.tif.to_hex, response: parsed.params.to_h }
          parsed
        end

        def case_nut_replay_rejected(ctx)
          session, browser, = raw_session(identity)
          req = session.query
          first = raw_post(browser, req.url, req.body, ctx, "query")
          check(!first.tif.error?, "the first query failed")
          replay = raw_post(browser, req.url, req.body, ctx, "replay")
          check(replay.tif.error?, "a replayed request was accepted (tif 0x#{replay.tif.to_hex})")
          check(!replay.tif.id_match? || replay.tif.command_failed?, "replay must not succeed")
        end

        def case_unknown_nut_is_transient(ctx)
          id = identity
          browser = transport
          page = @site.login_page(browser)
          bogus = page.sqrl_url.sub(/nut=[^&]+/, "nut=conformance-unknown-nut")
          session = Session.new(id.unlocked, bogus)
          req = session.query
          resp = raw_post(browser, req.url, req.body, ctx, "unknown nut")
          check(resp.tif.transient_error? || resp.tif.client_failure?,
                "unknown nut should be a transient error (or client failure), got 0x#{resp.tif.to_hex}")
        end

        def case_tampered_client_rejected(ctx)
          session, browser, = raw_session(identity)
          req = session.query
          client = req.body[/client=([^&]+)/, 1]
          flipped = client.dup
          flipped[5] = flipped[5] == "A" ? "B" : "A"
          resp = raw_post(browser, req.url, req.body.sub(client, flipped), ctx, "tampered client")
          check(resp.tif.client_failure? && resp.tif.command_failed?, "tampered client= accepted (0x#{resp.tif.to_hex})")
        end

        def case_wrong_server_echo_rejected(ctx)
          id = identity
          session, browser, page = raw_session(id)
          other = @site.login_page(transport)
          # sign a request whose server= is a different (valid) login URL
          foreign = Session.new(id.unlocked, other.sqrl_url).query
          url = page.sqrl_url.sub(/\As?qrl/, page.sqrl_url.start_with?("qrl") ? "http" : "https")
          resp = raw_post(browser, url, foreign.body, ctx, "wrong server echo")
          check(resp.tif.client_failure? && resp.tif.command_failed?, "mismatched server= accepted (0x#{resp.tif.to_hex})")
          _ = session
        end

        def case_bad_signature_rejected(ctx)
          id = identity
          session, browser, = raw_session(id)
          req = session.query
          ids = req.body[/ids=([^&]+)/, 1]
          other = Util.b64u_encode(Crypto.ed25519_sign(Util.random_bytes(32), "x"))
          resp = raw_post(browser, req.url, req.body.sub("ids=#{ids}", "ids=#{other}"), ctx, "bad ids")
          check(resp.tif.client_failure? && resp.tif.command_failed?, "bad ids= accepted (0x#{resp.tif.to_hex})")
        end

        def case_ident_without_lock_rejected(ctx)
          id = identity
          session, browser, = raw_session(id)
          req = session.query
          session.feed(raw_post(browser, req.url, req.body, ctx, "query").raw)
          skip("identity already known on this site") unless session.state.unknown?
          # an ident for a new account without suk/vuk must not create it
          ident = session.ident
          stripped_client = Protocol.decode_text(ident.body[/client=([^&]+)/, 1]).gsub(/^(suk|vuk)=.*\r\n/, "")
          client_b64 = Util.b64u_encode(stripped_client.b)
          server = ident.body[/server=([^&]+)/, 1]
          sig = Util.b64u_encode(Crypto.ed25519_sign(id.unlocked.site_seed(session.url.site_key_bytes), (client_b64 + server).b))
          resp = raw_post(browser, ident.url, "client=#{client_b64}&server=#{server}&ids=#{sig}", ctx, "ident without lock")
          check(resp.tif.command_failed?, "ident without suk/vuk created an account (0x#{resp.tif.to_hex})")
          check(!resp.tif.id_match?, "ident without suk/vuk reported ID_MATCH")
        end

        def case_cps_token_single_use(ctx)
          result = login(identity, ctx, cps: true)
          check(result.cps_url, "no CPS url= received")
          check(@site.success?(result.landing), "first use of the CPS URL did not log in")
          second = transport.get(result.cps_url)
          check(!@site.success?(second), "the CPS URL logged a second, cookie-less client in (HTTP #{second.status})")
        end

        def case_callback_without_token_rejected(ctx)
          result = login(identity, ctx, cps: true)
          check(result.cps_url, "no CPS url= received")
          bare = transport.get(@site.callback_without_token(result.cps_url))
          check(!@site.success?(bare), "the CPS callback without a token logged in (HTTP #{bare.status})")
        end

        def case_undefined_tif_bit_aborts_client(_ctx)
          body = Util.b64u_encode("ver=1\r\nnut=x\r\ntif=400\r\nqry=/cli\r\n")
          session = Session.new(identity.unlocked, "sqrl://example.com/cli?nut=x")
          begin
            session.feed(body)
            raise Failure, "a response with TIF 0x400 was accepted"
          rescue ProtocolError, FormatError
            nil
          end
        end

        # ---- robustness --------------------------------------------------------------------

        def case_transient_recovery(ctx)
          id = identity
          browser = transport
          page = @site.login_page(browser)
          bogus = page.sqrl_url.sub(/nut=[^&]+/, "nut=conformance-stale")
          result = agent(id, transport: browser, cps: false, poll: false).login(bogus)
          ctx.transcript.concat(result.transcript)
          check(result.tif_history.first.transient_error?, "the stale nut did not produce a transient error")
          check(result.authenticated?, "login did not recover from the transient error")
        end

        def case_concurrent_logins(ctx)
          results = Array.new(4) do
            Thread.new { login(identity, ctx, cps: false, poll: false) }
          end.map(&:value)
          check(results.all?(&:authenticated?), "a concurrent login failed")
          check(results.map(&:idk).uniq.size == results.size, "concurrent logins shared an idk")
        end
      end
    end
  end
end
