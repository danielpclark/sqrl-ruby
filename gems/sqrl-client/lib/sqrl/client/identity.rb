# frozen_string_literal: true

module SQRL
  module Client
    # An identity as a bot uses it: an unlocked {SQRL::UnlockedIdentity} plus, when known,
    # the Identity Unlock Key needed for +enable+, +remove+ and re-keying, optionally backed
    # by an S4 identity file.
    #
    #   SQRL::Client::Identity.load("bot.sqrl", password: "…")      # S4 file (binary or SQRLDATA text)
    #   SQRL::Client::Identity.from_textual(text, rescue_code: "…")  # rescue-only textual import
    #   SQRL::Client::Identity.create(password: "…")                 # brand new, returns the rescue code
    #   SQRL::Client::Identity.ephemeral                              # random IUK, no EnScrypt (tests)
    #   SQRL::Client::Identity.ephemeral("seed")                      # deterministic from a seed
    #   SQRL::Client::Identity.from_env                               # SQRL_IDENTITY_FILE / SQRL_IUK_HEX …
    class Identity
      # @return [SQRL::UnlockedIdentity]
      attr_reader :unlocked
      # @return [SQRL::S4Identity, nil] the identity file, when there is one
      attr_reader :s4
      # @return [String, nil] where the identity file lives
      attr_reader :path
      # @return [String, nil] the rescue code, only right after {.create} or {#rekey!}
      attr_reader :rescue_code

      # A fast clock for identity creation in tests: every call advances one second so a
      # one-second EnScrypt finishes after one iteration.
      def self.fast_clock
        t = 0
        -> { t += 1000 }
      end

      # Load an S4 identity file (binary +sqrldata+ or +SQRLDATA+ text) and unlock it.
      #
      # @param path [String]
      # @param password [String]
      # @param rescue_code [String, nil] also recover the IUK (slow; needed for enable/remove)
      def self.load(path, password:, rescue_code: nil)
        s4 = S4Identity.parse(File.binread(path))
        from_s4(s4, password: password, rescue_code: rescue_code, path: path)
      end

      # Unlock a parsed {SQRL::S4Identity}.
      def self.from_s4(s4, password:, rescue_code: nil, path: nil)
        unless s4.password_block?
          raise IdentityLocked,
                "identity file has no password block; import it with the rescue code"
        end

        identity = new(s4.unlock(password.to_s), s4: s4, path: path)
        identity.unlock_iuk!(rescue_code) if rescue_code
        identity
      end

      # Import a rescue-only textual identity (the base56 export) with its rescue code. The
      # IUK is recovered, so the identity can enable/remove right away. Pass +password:+ to
      # also build a password block (returned via {#s4}).
      def self.from_textual(text, rescue_code:, password: nil, settings: nil, now_ms: nil)
        s4 = S4Identity.parse_blocks(Textual.decode(text))
        iuk = s4.unlock_iuk(rescue_code)
        imk = SQRL::Identity.imk_from_iuk(iuk)
        previous = s4.type3 ? s4.type3.decrypt(imk) : []
        unlocked = UnlockedIdentity.from_iuk(iuk, previous)
        if password
          kw = now_ms ? { now_ms: now_ms } : {}
          s4.set_password(unlocked, password, settings || Storage::IdentitySettings.new, **kw)
        end
        new(unlocked, s4: s4, iuk: iuk)
      end

      # Create a brand-new identity. The rescue code is generated unless given and is
      # available as {#rescue_code}; the S4 file is {#s4} and is written to +path+ when
      # given.
      #
      # @param password [String]
      # @param rescue_code [String, nil] 24 digits (with or without dashes)
      # @param settings [SQRL::Storage::IdentitySettings, nil]
      # @param pw_seconds [Integer, nil] EnScrypt time for the password block (default 5)
      # @param rescue_seconds [Numeric, nil] EnScrypt time for the rescue block (default 5)
      # @param path [String, nil]
      # @param now_ms [#call, nil] clock override (see {.fast_clock}) for fast test identities
      def self.create(password:, rescue_code: nil, settings: nil, pw_seconds: nil, rescue_seconds: nil,
                      path: nil, now_ms: nil, &progress)
        settings ||= Storage::IdentitySettings.new
        settings = settings.dup.tap { |s| s.pw_verify_seconds = pw_seconds } if pw_seconds
        rescue_code ||= Storage.generate_rescue_code
        iuk = Util.random_bytes(32)
        kw = now_ms ? { now_ms: now_ms } : {}
        rescue_ms = ((rescue_seconds || 5) * 1000).to_i
        s4 = S4Identity.create(iuk, password, rescue_code, settings, rescue_ms, **kw, &progress)
        File.binwrite(path, s4.to_bytes) if path
        new(UnlockedIdentity.from_iuk(iuk), s4: s4, iuk: iuk, path: path,
                                            rescue_code: Storage.format_rescue_code(rescue_code))
      end

      # An identity straight from a 32-byte IUK, skipping EnScrypt and storage entirely.
      # With no seed the IUK is random; with a seed it is derived deterministically
      # (32 raw bytes are used as-is, anything else is hashed), which gives reproducible
      # identities for test suites.
      def self.ephemeral(seed = nil, previous: [])
        iuk = case seed
              when nil then Util.random_bytes(32)
              when String then seed.b.bytesize == 32 ? seed.b : Crypto.sha256("sqrl-client-ephemeral:#{seed.to_s.b}")
              else Crypto.sha256("sqrl-client-ephemeral:#{seed.to_s.b}")
              end
        new(UnlockedIdentity.from_iuk(iuk, previous), iuk: iuk, previous_iuks: previous)
      end

      # Build an identity from environment variables:
      #
      # * +SQRL_IUK_HEX+ – 64 hex characters: an ephemeral identity (tests, CI)
      # * +SQRL_IDENTITY_FILE+ with +SQRL_PASSWORD+ or +SQRL_PASSWORD_FILE+ – an S4 file
      # * +SQRL_RESCUE_CODE+ – optional, recovers the IUK for enable/remove
      #
      # @return [Identity, nil] nil when nothing is configured
      def self.from_env(env = ENV)
        if (hex = env["SQRL_IUK_HEX"]) && !hex.empty?
          return ephemeral(Util.hex_decode(hex))
        end

        file = env["SQRL_IDENTITY_FILE"]
        return nil if file.nil? || file.empty?

        password = env["SQRL_PASSWORD"]
        password = File.read(env["SQRL_PASSWORD_FILE"]).chomp if password.nil? && env["SQRL_PASSWORD_FILE"]
        raise IdentityLocked, "SQRL_PASSWORD or SQRL_PASSWORD_FILE is required with SQRL_IDENTITY_FILE" if password.nil?

        load(file, password: password, rescue_code: env["SQRL_RESCUE_CODE"])
      end

      # @api private
      def initialize(unlocked, s4: nil, iuk: nil, path: nil, rescue_code: nil, previous_iuks: nil)
        @unlocked = unlocked
        @s4 = s4
        @iuk = iuk&.b
        @path = path
        @rescue_code = rescue_code
        @previous_iuks = previous_iuks || unlocked.previous_iuks
      end

      # The Identity Unlock Key when it is known (ephemeral identities, freshly created
      # ones, or after {#unlock_iuk!}); nil otherwise.
      attr_reader :iuk

      # Whether +enable+/+remove+/+rekey!+ can run without a rescue code.
      def iuk? = !@iuk.nil?

      # Recover the IUK from the identity file's rescue block (slow: EnScrypt).
      #
      # @return [String] the IUK
      def unlock_iuk!(rescue_code)
        return @iuk if @iuk

        raise IdentityLocked, "this identity has no rescue block; the IUK cannot be recovered" unless @s4&.rescue_block?

        iuk = @s4.unlock_iuk(rescue_code)
        raise CryptoError, "rescue code does not belong to this identity" unless @unlocked.matches_iuk?(iuk)

        @iuk = iuk
      end

      # Re-key: a fresh IUK replaces the current one and the current one becomes the most
      # recent previous identity, exactly as a SQRL client's "rekey identity" does. Needs the
      # current IUK (ephemeral/created identities have it; file identities need
      # +rescue_code:+). File-backed identities are re-encrypted under +password:+ (and a new
      # rescue code, available as {#rescue_code}); the file at {#path} is rewritten.
      #
      # @return [self]
      def rekey!(password: nil, rescue_code: nil, new_rescue_code: nil, settings: nil, now_ms: nil, rescue_seconds: nil)
        old_iuk = @iuk || (rescue_code && unlock_iuk!(rescue_code))
        raise IdentityLocked, "re-keying needs the current IUK (rescue code)" unless old_iuk

        new_iuk = Util.random_bytes(32)
        if @s4
          raise ArgumentError, "password: is required to re-key a file-backed identity" unless password

          new_rescue_code ||= Storage.generate_rescue_code
          kw = now_ms ? { now_ms: now_ms } : {}
          rescue_ms = ((rescue_seconds || 5) * 1000).to_i
          @unlocked = @s4.rekey(@unlocked, old_iuk, new_iuk, password, new_rescue_code,
                                settings || @s4.settings, rescue_ms, **kw)
          @rescue_code = Storage.format_rescue_code(new_rescue_code)
          File.binwrite(@path, @s4.to_bytes) if @path
        else
          previous = ([old_iuk] + @unlocked.previous_iuks).first(Storage::MAX_PREVIOUS_KEYS)
          @unlocked = UnlockedIdentity.from_iuk(new_iuk, previous)
        end
        @iuk = new_iuk
        self
      end

      # A detached copy of this identity as it was before the most recent {#rekey!}:
      # handy for testing that a superseded identity is refused.
      def previous_identity(index = 0)
        iuk = @unlocked.previous_iuks[index]
        return nil unless iuk

        self.class.ephemeral(iuk)
      end

      # @return [Integer] number of previous identities carried
      def previous_count = @unlocked.previous_count

      # 16 hex characters identifying the identity without revealing key material.
      def fingerprint = @unlocked.fingerprint

      # Save the identity file (requires an S4-backed identity).
      def save(path = @path)
        raise IdentityLocked, "ephemeral identities have no file to save" unless @s4
        raise ArgumentError, "no path given" unless path

        File.binwrite(path, @s4.to_bytes)
        @path = path
      end

      # The identity file as +SQRLDATA+ text, or the IUK in hex for ephemeral identities
      # (both forms load back with {.load}/{.from_env}).
      def export
        @s4 ? @s4.to_text : Util.hex_encode(@iuk)
      end

      # @return [String] a short description with secret material redacted
      def inspect
        "#<SQRL::Client::Identity fingerprint=#{fingerprint} iuk=#{iuk? ? "known" : "locked"} " \
          "previous=#{previous_count}#{" path=#{@path}" if @path}>"
      end
      alias to_s inspect
    end
  end
end
