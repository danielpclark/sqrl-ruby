# frozen_string_literal: true

require "optparse"
require "json"
require "io/console"

module SQRL
  module Client
    # The +sqrl-client+ command-line tool.
    #
    #   sqrl-client identity create --out bot.sqrl
    #   sqrl-client login https://example.com/login --identity bot.sqrl --cookies-out jar.txt
    #   sqrl-client conformance https://example.com/login --report junit.xml
    #
    # Exit codes: 0 success, 1 protocol failure (the site refused), 2 transport failure,
    # 3 usage error.
    class CLI
      EXIT_OK = 0
      EXIT_PROTOCOL = 1
      EXIT_TRANSPORT = 2
      EXIT_USAGE = 3

      USAGE = <<~TEXT
        Usage: sqrl-client <command> [options]

        Commands:
          identity create   --out FILE [--password PW | --password-file F] [--pw-seconds N] [--rescue-seconds N]
          identity import   --textual FILE --rescue-code CODE --out FILE [--password PW]
          identity show     --identity FILE [--password PW] [--json]
          identity export   --identity FILE [--password PW] --format s4-text|textual|binary [--out FILE]
          identity rekey    --identity FILE --password PW --rescue-code CODE [--out FILE] [--rescue-seconds N]
          identity change-password --identity FILE --password OLD --new-password NEW [--pw-seconds N] [--out FILE]
          identity previous --identity FILE [--password PW]   list previous (superseded) identities
          login   URL       perform a SQRL login (creates the account if the site does not know you)
          query   URL       ask the site whether it knows the identity
          disable URL       disable SQRL login for the account
          enable  URL       re-enable it (needs --rescue-code or an --iuk-hex identity)
          remove  URL       remove the SQRL association (same requirement)
          conformance URL   run the server conformance suite against a login page
          version

        Identity options (login/query/disable/enable/remove):
          --identity FILE       S4 identity file (or set SQRL_IDENTITY_FILE)
          --password PW         password (or SQRL_PASSWORD / --password-file F / SQRL_PASSWORD_FILE)
          --password-file F
          --rescue-code CODE    24-digit rescue code (or SQRL_RESCUE_CODE), for enable/remove
          --iuk-hex HEX         ephemeral identity from a raw 64-hex IUK (or SQRL_IUK_HEX)

        Login options:
          --no-cps              do not request a Client Provided Session
          --alt-id ID           use an Alt-ID
          --refuse-unknown      fail instead of creating an account on an unknown site
          --ask N               answer a server ask= with button N (0, 1 or 2)
          --sqrlonly / --hardlock / --noiptest
          --cookies-out FILE    write the session cookies after login
          --cookies-format F    netscape (default) or json
          --allow-http          allow plain http for non-loopback hosts (testing only)
          --insecure            do not verify TLS certificates (testing only)
          --json                machine-readable output
          -v, --verbose         protocol trace on stderr

        Conformance options:
          --report FILE         write a JUnit XML report
          --feature NAME=on|off toggle a feature (cps, poll, rekey, remove, ask, sin, alt_id, negative, cps_single_use, concurrency)
          --only CASE[,CASE]    run only these cases
          --ask-button N        button to answer asks with (default 1)
      TEXT

      def self.run(argv = ARGV, out: $stdout, err: $stderr)
        new(out: out, err: err).run(argv)
      end

      def initialize(out: $stdout, err: $stderr)
        @out = out
        @err = err
      end

      # @return [Integer] exit code
      def run(argv)
        argv = argv.dup
        command = argv.shift
        case command
        when "identity" then identity_command(argv)
        when "login", "query", "disable", "enable", "remove" then protocol_command(command.to_sym, argv)
        when "conformance" then conformance_command(argv)
        when "version", "--version", "-V"
          @out.puts "sqrl-client #{SQRL::VERSION}"
          EXIT_OK
        when nil, "help", "--help", "-h"
          @out.puts USAGE
          command.nil? ? EXIT_USAGE : EXIT_OK
        else
          @err.puts "unknown command #{command.inspect}\n\n#{USAGE}"
          EXIT_USAGE
        end
      rescue OptionParser::ParseError, ArgumentError => e
        @err.puts "error: #{e.message}"
        EXIT_USAGE
      rescue TransportError => e
        @err.puts "transport error: #{e.message}"
        EXIT_TRANSPORT
      rescue AskRequired => e
        @err.puts "#{e.message} (use --ask N)"
        EXIT_PROTOCOL
      rescue LoginFailed => e
        @err.puts "failed (#{e.reason}, tif 0x#{e.tif&.to_hex}): #{e.message}"
        EXIT_PROTOCOL
      rescue SQRL::Error => e
        @err.puts "error: #{e.message}"
        EXIT_PROTOCOL
      end

      private

      # ---- identity ------------------------------------------------------------------------

      def identity_command(argv)
        sub = argv.shift
        opts = { pw_seconds: nil, rescue_seconds: nil }
        parser = OptionParser.new do |o|
          o.on("--out FILE") { |v| opts[:out] = v }
          o.on("--identity FILE") { |v| opts[:identity] = v }
          o.on("--password PW") { |v| opts[:password] = v }
          o.on("--password-file FILE") { |v| opts[:password] = File.read(v).chomp }
          o.on("--textual FILE") { |v| opts[:textual] = File.read(v) }
          o.on("--rescue-code CODE") { |v| opts[:rescue_code] = v }
          o.on("--pw-seconds N", Integer) { |v| opts[:pw_seconds] = v }
          o.on("--rescue-seconds N", Float) { |v| opts[:rescue_seconds] = v }
          o.on("--new-password PW") { |v| opts[:new_password] = v }
          o.on("--new-password-file FILE") { |v| opts[:new_password] = File.read(v).chomp }
          o.on("--format FORMAT", %w[s4-text textual binary]) { |v| opts[:format] = v }
          o.on("--json") { opts[:json] = true }
        end
        parser.parse!(argv)

        case sub
        when "create"
          raise ArgumentError, "--out FILE is required" unless opts[:out]

          password = opts[:password] || ENV["SQRL_PASSWORD"] || prompt_password("New identity password: ")
          id = Identity.create(password: password, path: opts[:out], pw_seconds: opts[:pw_seconds],
                               rescue_seconds: opts[:rescue_seconds])
          if opts[:json]
            @out.puts JSON.generate(path: opts[:out], rescue_code: id.rescue_code, fingerprint: id.fingerprint)
          else
            @out.puts "Identity written to #{opts[:out]} (fingerprint #{id.fingerprint})."
            @out.puts "Rescue code (write it down, it is shown once): #{id.rescue_code}"
          end
          EXIT_OK
        when "import"
          raise ArgumentError, "--textual FILE, --rescue-code CODE and --out FILE are required" unless opts[:textual] && opts[:rescue_code] && opts[:out]

          password = opts[:password] || ENV["SQRL_PASSWORD"] || prompt_password("Password for the imported identity: ")
          id = Identity.from_textual(opts[:textual], rescue_code: opts[:rescue_code], password: password)
          id.save(opts[:out])
          @out.puts opts[:json] ? JSON.generate(path: opts[:out], fingerprint: id.fingerprint) : "Identity written to #{opts[:out]} (fingerprint #{id.fingerprint})."
          EXIT_OK
        when "show"
          id = load_identity(identity: opts[:identity], password: opts[:password])
          info = { fingerprint: id.fingerprint, previous_identities: id.previous_count, iuk_known: id.iuk?,
                   edition: id.s4&.edition, file: id.path }
          @out.puts opts[:json] ? JSON.generate(info) : info.map { |k, v| "#{k}: #{v}" }.join("\n")
          EXIT_OK
        when "export" then identity_export(opts)
        when "rekey" then identity_rekey(opts)
        when "change-password" then identity_change_password(opts)
        when "previous" then identity_previous(opts)
        else
          raise ArgumentError, "identity needs one of: create, import, show, export, rekey, change-password, previous"
        end
      end

      # The identity file in one of its interchange forms:
      #   s4-text   the SQRLDATA text form of the whole file (password + rescue blocks)
      #   textual   the base56 "textual identity" (rescue blocks only; needs the rescue code to import)
      #   binary    the raw sqrldata file (requires --out)
      def identity_export(opts)
        format = opts[:format] or raise ArgumentError, "--format s4-text|textual|binary is required"
        id = load_identity(identity: opts[:identity], password: opts[:password])
        raise IdentityLocked, "ephemeral identities have no file to export" unless id.s4

        content =
          case format
          when "s4-text" then id.s4.to_text
          when "textual" then Textual.format_for_display(Textual.encode(id.s4.rescue_blocks_to_bytes))
          when "binary"
            raise ArgumentError, "--out FILE is required for the binary format" unless opts[:out]

            id.s4.to_bytes
          end
        if opts[:out]
          File.binwrite(opts[:out], content)
          File.chmod(0o600, opts[:out])
          @out.puts opts[:json] ? JSON.generate(path: opts[:out], format: format, bytes: content.bytesize) : "Wrote #{format} identity to #{opts[:out]}."
        else
          @out.puts content
        end
        EXIT_OK
      end

      # A fresh Identity Unlock Key; the current one becomes the most recent previous
      # identity, so sites re-key the account on the next login. Prints the new rescue code.
      def identity_rekey(opts)
        id = load_identity(identity: opts[:identity], password: opts[:password])
        rescue_code = opts[:rescue_code] || ENV["SQRL_RESCUE_CODE"] or raise ArgumentError, "--rescue-code CODE is required to re-key"
        password = opts[:new_password] || opts[:password] || ENV["SQRL_PASSWORD"]
        id.rekey!(password: password, rescue_code: rescue_code, rescue_seconds: opts[:rescue_seconds])
        id.save(opts[:out]) if opts[:out]
        if opts[:json]
          @out.puts JSON.generate(path: id.path, fingerprint: id.fingerprint, previous_identities: id.previous_count,
                                  rescue_code: id.rescue_code)
        else
          @out.puts "Identity re-keyed and written to #{id.path} (fingerprint #{id.fingerprint}, #{id.previous_count} previous)."
          @out.puts "New rescue code (write it down, it is shown once): #{id.rescue_code}"
        end
        EXIT_OK
      end

      # Re-encrypt the password block under a new password (the rescue block is untouched).
      def identity_change_password(opts)
        new_password = opts[:new_password] or raise ArgumentError, "--new-password PW (or --new-password-file) is required"
        id = load_identity(identity: opts[:identity], password: opts[:password])
        raise IdentityLocked, "ephemeral identities have no password to change" unless id.s4

        settings = id.s4.settings
        settings.pw_verify_seconds = opts[:pw_seconds] if opts[:pw_seconds]
        id.s4.set_password(id.unlocked, new_password, settings)
        id.save(opts[:out] || id.path)
        @out.puts opts[:json] ? JSON.generate(path: id.path, fingerprint: id.fingerprint) : "Password changed; identity written to #{id.path}."
        EXIT_OK
      end

      # Previous (superseded) identities carried by the file, most recent first.
      def identity_previous(opts)
        id = load_identity(identity: opts[:identity], password: opts[:password])
        rows = (0...id.previous_count).map { |i| { index: i, fingerprint: id.previous_identity(i).fingerprint } }
        if opts[:json]
          @out.puts JSON.generate(current: id.fingerprint, previous: rows)
        else
          @out.puts "current: #{id.fingerprint}"
          @out.puts(rows.empty? ? "previous: none" : rows.map { |r| "previous[#{r[:index]}]: #{r[:fingerprint]}" }.join("\n"))
        end
        EXIT_OK
      end

      # ---- login / query / disable / enable / remove ---------------------------------------

      def protocol_command(command, argv)
        opts = { cps: true, options: {}, unknown_site: :create }
        parser = OptionParser.new do |o|
          o.on("--identity FILE") { |v| opts[:identity] = v }
          o.on("--password PW") { |v| opts[:password] = v }
          o.on("--password-file FILE") { |v| opts[:password] = File.read(v).chomp }
          o.on("--rescue-code CODE") { |v| opts[:rescue_code] = v }
          o.on("--iuk-hex HEX") { |v| opts[:iuk_hex] = v }
          o.on("--no-cps") { opts[:cps] = false }
          o.on("--alt-id ID") { |v| opts[:alt_id] = v }
          o.on("--refuse-unknown") { opts[:unknown_site] = :refuse }
          o.on("--ask N", Integer) { |v| opts[:ask] = v }
          o.on("--sqrlonly") { opts[:options][:sqrlonly] = true }
          o.on("--hardlock") { opts[:options][:hardlock] = true }
          o.on("--noiptest") { opts[:options][:noiptest] = true }
          o.on("--cookies-out FILE") { |v| opts[:cookies_out] = v }
          o.on("--cookies-format FORMAT", %w[netscape json]) { |v| opts[:cookies_format] = v }
          o.on("--allow-http") { opts[:allow_http] = true }
          o.on("--insecure") { opts[:insecure] = true }
          o.on("--json") { opts[:json] = true }
          o.on("-v", "--verbose") { opts[:verbose] = true }
        end
        parser.parse!(argv)
        target = argv.shift
        raise ArgumentError, "#{command} needs a URL" unless target

        identity = load_identity(**opts.slice(:identity, :password, :iuk_hex))
        logger = opts[:verbose] ? stderr_logger : nil
        transport = Transport.new(allow_http: opts[:allow_http] ? true : :loopback, verify_tls: !opts[:insecure],
                                  logger: logger)
        agent = Agent.new(identity: identity, transport: transport, cps: opts[:cps], unknown_site: opts[:unknown_site],
                          options: opts[:options], alt_id: opts[:alt_id], logger: logger,
                          ask_handler: opts.key?(:ask) ? ->(_ask) { opts[:ask] } : nil)
        result =
          case command
          when :login then agent.login(target)
          when :query then agent.query(target)
          when :disable then agent.disable(target)
          when :enable then agent.enable(target, rescue_code: opts[:rescue_code] || ENV["SQRL_RESCUE_CODE"])
          when :remove then agent.remove(target, rescue_code: opts[:rescue_code] || ENV["SQRL_RESCUE_CODE"])
          end
        write_cookies(transport, opts) if opts[:cookies_out]
        if opts[:json]
          @out.puts JSON.generate(result.to_h)
        else
          @out.puts describe(result)
        end
        EXIT_OK
      end

      def describe(result)
        lines = ["#{result.command}: #{result.state.kind}#{result.state.disabled? ? ' (disabled)' : ''} tif=0x#{result.tif&.to_hex}"]
        lines << "idk: #{result.idk}"
        lines << "authenticated: #{result.authenticated?}#{result.created? ? ' (account created)' : ''}#{result.rekeyed? ? ' (account re-keyed)' : ''}" if result.command != :query
        lines << "cps url: #{result.cps_url}" if result.cps_url
        lines << "landing: HTTP #{result.landing.status} #{result.landing.final_url}" if result.landing
        lines.join("\n")
      end

      def write_cookies(transport, opts)
        content = opts[:cookies_format] == "json" ? JSON.pretty_generate(transport.cookies_as_hashes) : transport.cookies_netscape
        File.write(opts[:cookies_out], content)
        File.chmod(0o600, opts[:cookies_out])
      end

      # ---- conformance ---------------------------------------------------------------------

      def conformance_command(argv)
        opts = { features: {}, ask_button: 1 }
        parser = OptionParser.new do |o|
          o.on("--report FILE") { |v| opts[:report] = v }
          o.on("--feature NAME=VALUE") do |v|
            name, value = v.split("=", 2)
            opts[:features][name.to_sym] = %w[on true yes 1].include?(value.to_s.downcase)
          end
          o.on("--only CASES") { |v| opts[:only] = v.split(",").map(&:strip) }
          o.on("--ask-button N", Integer) { |v| opts[:ask_button] = v }
          o.on("--allow-http") { opts[:allow_http] = true }
          o.on("--insecure") { opts[:insecure] = true }
          o.on("--json") { opts[:json] = true }
          o.on("-v", "--verbose") { opts[:verbose] = true }
        end
        parser.parse!(argv)
        login_url = argv.shift
        raise ArgumentError, "conformance needs the login page URL" unless login_url

        require "sqrl/client/conformance"
        logger = opts[:verbose] ? stderr_logger : nil
        transport_factory = lambda do
          Transport.new(allow_http: opts[:allow_http] ? true : :loopback, verify_tls: !opts[:insecure], logger: logger)
        end
        runner = Conformance::Runner.new(login_url: login_url, features: opts[:features], only: opts[:only],
                                         ask_button: opts[:ask_button], transport_factory: transport_factory,
                                         logger: logger)
        report = runner.run
        File.write(opts[:report], report.to_junit_xml) if opts[:report]
        @out.puts(opts[:json] ? JSON.generate(report.to_h) : report.to_s)
        report.passed? ? EXIT_OK : EXIT_PROTOCOL
      end

      # ---- helpers ---------------------------------------------------------------------------

      def load_identity(identity: nil, password: nil, iuk_hex: nil)
        iuk_hex ||= ENV["SQRL_IUK_HEX"]
        return Identity.ephemeral(Util.hex_decode(iuk_hex)) if iuk_hex && !iuk_hex.empty?

        file = identity || ENV["SQRL_IDENTITY_FILE"]
        raise ArgumentError, "an identity is required (--identity FILE, --iuk-hex HEX, SQRL_IDENTITY_FILE or SQRL_IUK_HEX)" if file.nil?

        password ||= ENV["SQRL_PASSWORD"]
        password ||= File.read(ENV["SQRL_PASSWORD_FILE"]).chomp if ENV["SQRL_PASSWORD_FILE"]
        password ||= prompt_password("Identity password: ")
        Identity.load(file, password: password)
      end

      def prompt_password(label)
        raise ArgumentError, "a password is required (--password, --password-file or SQRL_PASSWORD)" unless $stdin.tty?

        @err.print label
        pw = $stdin.noecho(&:gets).to_s.chomp
        @err.puts
        pw
      end

      def stderr_logger
        require "logger"
        Logger.new(@err, level: Logger::DEBUG, formatter: ->(_sev, _time, _prog, msg) { "#{msg}\n" })
      end
    end
  end
end
