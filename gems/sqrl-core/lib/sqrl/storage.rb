# frozen_string_literal: true

module SQRL
  # The S4 ("SQRL Secure Storage System") identity file format.
  #
  # An identity file starts with the 8 byte header +sqrldata+ (binary) or +SQRLDATA+
  # followed by base64url text, and then a sequence of length-prefixed blocks:
  #
  # * Type 1 (125 bytes): the password-protected IMK and ILK plus the user's settings.
  #   AES-256-GCM, key = EnScrypt(password, salt, logN, iterations), IV from the block,
  #   AAD = the 45 plaintext bytes of the block.
  # * Type 2 (73 bytes): the rescue-code-protected IUK. AES-256-GCM, key =
  #   EnScrypt(rescue code digits, salt, logN, iterations), IV = 12 zero bytes,
  #   AAD = the 25 plaintext bytes of the block.
  # * Type 3 (54/86/118/150 bytes): up to four previous IUKs. AES-256-GCM, key = IMK,
  #   IV = 12 zero bytes, AAD = the 6 plaintext bytes of the block.
  #
  # Unknown block types are preserved verbatim so that files written by other clients
  # survive a round trip.
  module Storage
    # Binary file header.
    HEADER_BINARY = "sqrldata".b.freeze
    # Header of the base64url textual representation.
    HEADER_TEXT = "SQRLDATA".b.freeze

    # Type 1 option flag: the client should check for updates.
    FLAG_CHECK_FOR_UPDATES = 0x0001
    # Type 1 option flag: the client may update itself automatically.
    FLAG_UPDATE_AUTOMATICALLY = 0x0002
    # Type 1 option flag: request that sites disable non-SQRL authentication (+sqrlonly+).
    FLAG_SQRL_ONLY = 0x0004
    # Type 1 option flag: request that sites disable account recovery by other means (+hardlock+).
    FLAG_NO_BYPASS = 0x0008
    # Type 1 option flag: warn of a possible MITM attack when the server reports that the
    # query's IP does not match the IP that requested the SQRL URL.
    FLAG_WARN_MITM = 0x0010
    # Type 1 option flag: discard the QuickPass when the system blanks, sleeps or suspends.
    FLAG_CLEAR_QUICKPASS_ON_SLEEP = 0x0020
    # Type 1 option flag: discard the QuickPass when the user is switched.
    FLAG_CLEAR_QUICKPASS_ON_SWITCH = 0x0040
    # Type 1 option flag: discard the QuickPass after the idle timeout (minutes) elapses.
    FLAG_CLEAR_QUICKPASS_ON_IDLE = 0x0080
    # Type 1 option flag: warn whenever a non-CPS authentication is attempted.
    FLAG_WARN_NON_CPS = 0x0100
    # Default option flags for a newly created identity (0x01F3, per the S4 specification).
    DEFAULT_OPTION_FLAGS = FLAG_CHECK_FOR_UPDATES |
                           FLAG_UPDATE_AUTOMATICALLY |
                           FLAG_WARN_MITM |
                           FLAG_CLEAR_QUICKPASS_ON_SLEEP |
                           FLAG_CLEAR_QUICKPASS_ON_SWITCH |
                           FLAG_CLEAR_QUICKPASS_ON_IDLE |
                           FLAG_WARN_NON_CPS

    # Maximum number of previous IUKs stored in a type 3 block.
    MAX_PREVIOUS_KEYS = 4

    ZERO_IV = ("\0" * 12).b.freeze
    TYPE1_LEN = 125
    TYPE1_PT_LEN = 45
    TYPE2_LEN = 73
    TYPE2_PT_LEN = 25
    TYPE3_PT_LEN = 6
    private_constant :ZERO_IV, :TYPE1_LEN, :TYPE1_PT_LEN, :TYPE2_LEN, :TYPE2_PT_LEN, :TYPE3_PT_LEN

    # Normalize user-typed secret text the way all SQRL clients must before EnScrypt:
    # Unicode NFKC composition, then UTF-8 (SQRL Cryptography, "Processing User Input").
    def self.normalize_password(password)
      password.to_s.encode("UTF-8").unicode_normalize(:nfkc).b
    end

    # Generate a new 24-digit rescue code from 256 bits of entropy.
    def self.generate_rescue_code
      rescue_code_from_entropy(Util.random_bytes(32))
    end

    # Deterministic core of .generate_rescue_code: digits are extracted by repeated long
    # division of the 256-bit big-endian number by 10 (the code is +entropy mod 10**24+,
    # which is uniform to within 2**-176).
    def self.rescue_code_from_entropy(entropy)
      raise ArgumentError, "entropy must be 32 bytes" unless entropy.bytesize == 32

      num = entropy.bytes
      digits = Array.new(24) do
        rem = 0
        num.map! do |byte|
          cur = (rem << 8) | byte
          rem = cur % 10
          cur / 10
        end
        rem
      end
      digits.join
    end

    # Strip separators and whitespace from a rescue code and verify it has 24 digits.
    def self.normalize_rescue_code(code)
      code = code.to_s
      digits = code.delete("^0-9")
      non_digits = code.match?(/[^0-9\s-]/)
      raise FormatError, "a rescue code is 24 decimal digits" if digits.length != 24 || non_digits

      digits
    end

    # Format a rescue code as six groups of four digits separated by dashes.
    def self.format_rescue_code(code)
      code.to_s.scan(/.{1,4}/).join("-")
    end

    # Strip leading and trailing ASCII whitespace from a binary string.
    def self.trim_ascii(bytes)
      bytes.b.sub(/\A[ \t\r\n\f\v]+/, "").sub(/[ \t\r\n\f\v]+\z/, "")
    end

    # User-adjustable settings stored in the plaintext part of the type 1 block.
    IdentitySettings = Struct.new(:option_flags, :hint_length, :pw_verify_seconds,
                                  :idle_timeout_minutes, :log_n, keyword_init: true) do
      def initialize(option_flags: DEFAULT_OPTION_FLAGS, hint_length: 4, pw_verify_seconds: 5,
                     idle_timeout_minutes: 15, log_n: Crypto::DEFAULT_LOG_N)
        super
      end
    end

    # Type 1 block: password-encrypted IMK and ILK.
    class Type1Block
      attr_accessor :iv, :salt, :settings, :iterations, :enc_imk, :enc_ilk, :tag

      def initialize(iv:, salt:, settings:, iterations:, enc_imk:, enc_ilk:, tag:)
        @iv = iv.b
        @salt = salt.b
        @settings = settings
        @iterations = iterations
        @enc_imk = enc_imk.b
        @enc_ilk = enc_ilk.b
        @tag = tag.b
      end

      # The 45 plaintext bytes (which double as the AES-GCM additional authenticated data).
      def plaintext
        [TYPE1_LEN, 1, TYPE1_PT_LEN].pack("vvv") + @iv + @salt +
          [@settings.log_n, @iterations, @settings.option_flags, @settings.hint_length,
           @settings.pw_verify_seconds, @settings.idle_timeout_minutes].pack("CVvCCv")
      end

      # Serialize the full 125-byte block.
      def to_bytes
        plaintext + @enc_imk + @enc_ilk + @tag
      end

      def self.parse(b)
        raise FormatError, "type 1 block must be #{TYPE1_LEN} bytes, got #{b.bytesize}" unless b.bytesize == TYPE1_LEN

        pt_len = Util.le_u16(b, 4)
        raise FormatError, "unsupported type 1 plaintext length #{pt_len}" unless pt_len == TYPE1_PT_LEN

        new(
          iv: b.byteslice(6, 12),
          salt: b.byteslice(18, 16),
          settings: IdentitySettings.new(
            log_n: b.getbyte(34),
            option_flags: Util.le_u16(b, 39),
            hint_length: b.getbyte(41),
            pw_verify_seconds: b.getbyte(42),
            idle_timeout_minutes: Util.le_u16(b, 43)
          ),
          iterations: Util.le_u32(b, 35),
          enc_imk: b.byteslice(45, 32),
          enc_ilk: b.byteslice(77, 32),
          tag: b.byteslice(109, 16)
        )
      end

      # Derive the AES key from the password (slow: runs EnScrypt for +iterations+). The
      # block, if given, receives the number of completed iterations.
      def derive_key(password, &progress)
        pw = Storage.normalize_password(password)
        key = Crypto.enscrypt_iterations(pw, @salt, @settings.log_n, @iterations, &progress)
        Util.wipe(pw)
        key
      end

      # Decrypt IMK and ILK with an already-derived key. Returns +[imk, ilk]+.
      def decrypt_with_key(key)
        pt = Crypto.aes_gcm_decrypt(key, @iv, plaintext, @enc_imk + @enc_ilk + @tag)
        [pt.byteslice(0, 32), pt.byteslice(32, 32)]
      rescue CryptoError
        raise CryptoError, "incorrect password"
      end

      # Build a fresh block encrypting +imk+/+ilk+ under +password+, running EnScrypt for
      # +settings.pw_verify_seconds+ (as measured by +now_ms+). The block, if given,
      # receives +(elapsed_ms, duration_ms)+.
      def self.encrypt(imk, ilk, password, settings, now_ms: Crypto.method(:monotonic_ms), &progress)
        salt = Util.random_bytes(16)
        iv = Util.random_bytes(12)
        duration_ms = [settings.pw_verify_seconds, 1].max * 1000
        pw = Storage.normalize_password(password)
        key, iterations = Crypto.enscrypt_duration(pw, salt, settings.log_n, duration_ms, now_ms: now_ms, &progress)
        Util.wipe(pw)
        block = encrypt_with_key(imk, ilk, key, salt, iv, iterations, settings)
        Util.wipe(key)
        block
      end

      # Build a block with a pre-derived key (used by tests and for deterministic rebuilds).
      def self.encrypt_with_key(imk, ilk, key, salt, iv, iterations, settings)
        block = new(iv: iv, salt: salt, settings: settings, iterations: iterations,
                    enc_imk: "\0" * 32, enc_ilk: "\0" * 32, tag: "\0" * 16)
        ct = Crypto.aes_gcm_encrypt(key, block.iv, block.plaintext, imk.b + ilk.b)
        block.enc_imk = ct.byteslice(0, 32)
        block.enc_ilk = ct.byteslice(32, 32)
        block.tag = ct.byteslice(64, 16)
        block
      end

      def ==(other)
        other.is_a?(Type1Block) && to_bytes == other.to_bytes
      end
      alias eql? ==

      def hash
        to_bytes.hash
      end
    end

    # Type 2 block: rescue-code-encrypted IUK.
    class Type2Block
      attr_accessor :salt, :log_n, :iterations, :enc_iuk, :tag

      def initialize(salt:, log_n:, iterations:, enc_iuk:, tag:)
        @salt = salt.b
        @log_n = log_n
        @iterations = iterations
        @enc_iuk = enc_iuk.b
        @tag = tag.b
      end

      # The 25 plaintext bytes (also the AAD).
      def plaintext
        [TYPE2_LEN, 2].pack("vv") + @salt + [@log_n, @iterations].pack("CV")
      end

      # Serialize the full 73-byte block.
      def to_bytes
        plaintext + @enc_iuk + @tag
      end

      def self.parse(b)
        raise FormatError, "type 2 block must be #{TYPE2_LEN} bytes, got #{b.bytesize}" unless b.bytesize == TYPE2_LEN

        new(salt: b.byteslice(4, 16), log_n: b.getbyte(20), iterations: Util.le_u32(b, 21),
            enc_iuk: b.byteslice(25, 32), tag: b.byteslice(57, 16))
      end

      # Decrypt the IUK with the rescue code (slow: runs EnScrypt for +iterations+).
      def decrypt(rescue_code, &progress)
        digits = Storage.normalize_rescue_code(rescue_code)
        key = Crypto.enscrypt_iterations(digits, @salt, @log_n, @iterations, &progress)
        begin
          Crypto.aes_gcm_decrypt(key, ZERO_IV, plaintext, @enc_iuk + @tag)
        rescue CryptoError
          raise CryptoError, "incorrect rescue code"
        ensure
          Util.wipe(key)
        end
      end

      # Encrypt an IUK under a rescue code, running EnScrypt for +duration_ms+.
      def self.encrypt(iuk, rescue_code, log_n, duration_ms, now_ms: Crypto.method(:monotonic_ms), &progress)
        digits = Storage.normalize_rescue_code(rescue_code)
        salt = Util.random_bytes(16)
        key, iterations = Crypto.enscrypt_duration(digits, salt, log_n, duration_ms, now_ms: now_ms, &progress)
        block = encrypt_with_key(iuk, key, salt, log_n, iterations)
        Util.wipe(key)
        block
      end

      # Encrypt with a pre-derived key.
      def self.encrypt_with_key(iuk, key, salt, log_n, iterations)
        block = new(salt: salt, log_n: log_n, iterations: iterations, enc_iuk: "\0" * 32, tag: "\0" * 16)
        ct = Crypto.aes_gcm_encrypt(key, ZERO_IV, block.plaintext, iuk.b)
        block.enc_iuk = ct.byteslice(0, 32)
        block.tag = ct.byteslice(32, 16)
        block
      end

      def ==(other)
        other.is_a?(Type2Block) && to_bytes == other.to_bytes
      end
      alias eql? ==

      def hash
        to_bytes.hash
      end
    end

    # Type 3 block: previous IUKs encrypted under the current IMK.
    class Type3Block
      # The identity's "edition": a counter incremented once per re-keying. It is part of the
      # authenticated plaintext, so it can be shown without the password. The number of
      # stored keys is given by the block length, not by this field.
      attr_accessor :edition
      # Encrypted previous IUKs, most recent first (1 to 4 entries).
      attr_accessor :enc_keys
      attr_accessor :tag

      def initialize(edition:, enc_keys:, tag:)
        @edition = edition
        @enc_keys = enc_keys.map(&:b)
        @tag = tag.b
      end

      # Total block length for this many keys.
      def length
        TYPE3_PT_LEN + (32 * @enc_keys.length) + 16
      end
      alias len length

      # Whether the block holds no keys (never true for a well-formed block).
      def empty?
        @enc_keys.empty?
      end

      # The 6 plaintext bytes (also the AAD).
      def plaintext
        [length, 3, @edition].pack("vvv")
      end

      def to_bytes
        plaintext + @enc_keys.join + @tag
      end

      def self.parse(b)
        raise FormatError, "type 3 block too short" if b.bytesize < TYPE3_PT_LEN + 32 + 16

        edition = Util.le_u16(b, 4)
        raise FormatError, "type 3 block has edition 0" if edition.zero?

        body = b.bytesize - TYPE3_PT_LEN - 16
        if (body % 32) != 0 || body.zero? || body / 32 > MAX_PREVIOUS_KEYS
          raise FormatError, "type 3 block length #{b.bytesize} is not 54, 86, 118 or 150"
        end

        count = body / 32
        enc_keys = Array.new(count) { |i| b.byteslice(TYPE3_PT_LEN + (32 * i), 32) }
        new(edition: edition, enc_keys: enc_keys, tag: b.byteslice(-16, 16))
      end

      # Decrypt the previous IUKs with the current IMK.
      def decrypt(imk)
        pt = Crypto.aes_gcm_decrypt(imk, ZERO_IV, plaintext, @enc_keys.join + @tag)
        pt.bytes.each_slice(32).map { |c| c.pack("C*") }
      rescue CryptoError
        raise CryptoError, "previous identity block does not verify"
      end

      # Encrypt previous IUKs (most recent first; at most four are kept) under +imk+ with the
      # given edition number. Returns nil when there are no keys.
      def self.encrypt(previous_iuks, imk, edition)
        keys = previous_iuks.first(MAX_PREVIOUS_KEYS)
        return nil if keys.empty?

        block = new(edition: [edition, 1].max, enc_keys: Array.new(keys.length) { "\0" * 32 }, tag: "\0" * 16)
        ct = Crypto.aes_gcm_encrypt(imk, ZERO_IV, block.plaintext, keys.map(&:b).join)
        block.enc_keys = Array.new(keys.length) { |i| ct.byteslice(32 * i, 32) }
        block.tag = ct.byteslice(32 * keys.length, 16)
        block
      end

      def ==(other)
        other.is_a?(Type3Block) && to_bytes == other.to_bytes
      end
      alias eql? ==

      def hash
        to_bytes.hash
      end
    end
  end

  # A parsed S4 identity file.
  class S4Identity
    include Storage

    # Password block (Storage::Type1Block or nil).
    attr_accessor :type1
    # Rescue code block (Storage::Type2Block or nil).
    attr_accessor :type2
    # Previous identities block (Storage::Type3Block or nil).
    attr_accessor :type3
    # Blocks of unknown type, preserved verbatim (each including its length/type prefix).
    attr_accessor :unknown

    def initialize(type1: nil, type2: nil, type3: nil, unknown: [])
      @type1 = type1
      @type2 = type2
      @type3 = type3
      @unknown = unknown.map(&:b)
    end

    # Parse either the binary (+sqrldata+) or the textual base64url (+SQRLDATA+) form.
    def self.parse(input)
      trimmed = Storage.trim_ascii(input)
      raise FormatError, "identity data too short" if trimmed.bytesize < 8

      header = trimmed.byteslice(0, 8)
      if header == HEADER_TEXT
        text = trimmed.byteslice(8..)
        raise FormatError, "invalid SQRLDATA text" unless text.force_encoding("UTF-8").valid_encoding?

        return parse_blocks(Util.b64u_decode(text))
      end
      return parse_blocks(trimmed.byteslice(8..)) if header == HEADER_BINARY

      raise FormatError, "missing sqrldata header"
    end

    # Parse a sequence of blocks without the file header (used for the textual identity too).
    def self.parse_blocks(data)
      data = data.b
      id = new
      while data.bytesize >= 4
        len = Util.le_u16(data, 0)
        typ = Util.le_u16(data, 2)
        if len.zero?
          # zero padding (textual identities may carry trailing zero bytes)
          break if data.each_byte.all?(&:zero?)

          raise FormatError, "zero-length block"
        end
        if len < 4 || len > data.bytesize
          raise FormatError, "block of type #{typ} claims #{len} bytes but only #{data.bytesize} remain"
        end

        block = data.byteslice(0, len)
        # "Any client encountering an identity containing more than one of either type
        # should reject the entire identity as suspicious and invalid."
        duplicate = case typ
                    when 1 then !id.type1.nil?
                    when 2 then !id.type2.nil?
                    when 3 then !id.type3.nil?
                    else false
                    end
        raise FormatError, "identity contains more than one type #{typ} block" if duplicate

        case typ
        when 1 then id.type1 = Type1Block.parse(block)
        when 2 then id.type2 = Type2Block.parse(block)
        when 3 then id.type3 = Type3Block.parse(block)
        else id.unknown << block
        end
        data = data.byteslice(len..)
      end
      raise FormatError, "trailing garbage after last block" if data.each_byte.any? { |b| b != 0 }
      if id.type1.nil? && id.type2.nil?
        raise FormatError, "identity contains neither a password nor a rescue block"
      end

      id
    end

    # Serialize the blocks (type 1, 2, 3, then unknown) without a header.
    def blocks_to_bytes
      out = +"".b
      out << @type1.to_bytes if @type1
      out << @type2.to_bytes if @type2
      out << @type3.to_bytes if @type3
      @unknown.each { |u| out << u }
      out
    end

    # The type 2 + type 3 blocks only: what the textual identity and the rescue-only export
    # contain. (Type 1 is omitted because it is tied to the password of this installation.)
    def rescue_blocks_to_bytes
      out = +"".b
      out << @type2.to_bytes if @type2
      out << @type3.to_bytes if @type3
      out
    end

    # Binary +sqrldata+ file.
    def to_bytes
      HEADER_BINARY + blocks_to_bytes
    end

    # Textual +SQRLDATA+ + base64url representation.
    def to_text
      "SQRLDATA#{Util.b64u_encode(blocks_to_bytes)}"
    end

    # A copy containing only the rescue (type 2) and previous (type 3) blocks.
    def rescue_only
      S4Identity.new(type2: @type2, type3: @type3)
    end

    # Settings from the type 1 block, or defaults.
    def settings
      @type1 ? @type1.settings.dup : IdentitySettings.new
    end

    # The identity's edition: 0 for a never re-keyed identity, else the type 3 counter.
    def edition
      @type3 ? @type3.edition : 0
    end

    def password_block?
      !@type1.nil?
    end

    def rescue_block?
      !@type2.nil?
    end

    # Derive the password key (slow). The block receives completed EnScrypt iterations out
    # of +type1.iterations+.
    def derive_password_key(password, &progress)
      raise FormatError, "identity has no password block" unless @type1

      @type1.derive_key(password, &progress)
    end

    # Unlock the identity with an already-derived password key.
    def unlock_with_key(key)
      raise FormatError, "identity has no password block" unless @type1

      imk, ilk = @type1.decrypt_with_key(key)
      previous = @type3 ? @type3.decrypt(imk) : []
      UnlockedIdentity.new(imk, ilk, previous)
    end

    # Unlock the identity with the password (slow).
    def unlock(password, &progress)
      key = derive_password_key(password, &progress)
      unlock_with_key(key)
    ensure
      Util.wipe(key) if key
    end

    # Decrypt the IUK with the rescue code (slow).
    def unlock_iuk(rescue_code, &progress)
      raise FormatError, "identity has no rescue code block" unless @type2

      @type2.decrypt(rescue_code, &progress)
    end

    # Create a complete new identity file from an IUK.
    #
    # +rescue_duration_ms+ controls how long EnScrypt runs for the rescue block (the
    # reference client uses a long time because the rescue code is only 24 digits). The
    # block, if given, receives +(stage, elapsed_ms, duration_ms)+ with stage "password" or
    # "rescue".
    def self.create(iuk, password, rescue_code, settings = IdentitySettings.new, rescue_duration_ms = 5000,
                    now_ms: Crypto.method(:monotonic_ms), &progress)
      imk = Identity.imk_from_iuk(iuk)
      ilk = Identity.ilk_from_iuk(iuk)
      type1 = Type1Block.encrypt(imk, ilk, password, settings, now_ms: now_ms) do |a, b|
        progress&.call("password", a, b)
      end
      type2 = Type2Block.encrypt(iuk, rescue_code, settings.log_n, rescue_duration_ms, now_ms: now_ms) do |a, b|
        progress&.call("rescue", a, b)
      end
      Util.wipe(imk)
      Util.wipe(ilk)
      new(type1: type1, type2: type2)
    end

    # Re-encrypt the type 1 (and type 3) blocks for an unlocked identity under a new
    # password / settings. Used for password changes, settings changes and after importing a
    # rescue-only identity. The block receives +(elapsed_ms, duration_ms)+.
    def set_password(identity, password, settings = self.settings, now_ms: Crypto.method(:monotonic_ms), &progress)
      @type1 = Type1Block.encrypt(identity.imk, identity.ilk, password, settings, now_ms: now_ms, &progress)
      edition = [self.edition, identity.previous_iuks.length].max
      @type3 = Type3Block.encrypt(identity.previous_iuks, identity.imk, edition)
      self
    end

    # Re-key the identity: a new IUK is supplied, the old IUK (recovered with the old rescue
    # code) moves to the front of the previous-identity list, and new type 1 / 2 / 3 blocks
    # are produced for +new_password+ and +new_rescue_code+.
    #
    # Returns the new unlocked identity (with the previous IUKs).
    def rekey(old_identity, old_iuk, new_iuk, new_password, new_rescue_code, settings = self.settings,
              rescue_duration_ms = 5000, now_ms: Crypto.method(:monotonic_ms), &progress)
      previous = [old_iuk.b] + old_identity.previous_iuks.first(MAX_PREVIOUS_KEYS - 1)
      new_identity = UnlockedIdentity.from_iuk(new_iuk, previous)
      type1 = Type1Block.encrypt(new_identity.imk, new_identity.ilk, new_password, settings, now_ms: now_ms) do |a, b|
        progress&.call("password", a, b)
      end
      type2 = Type2Block.encrypt(new_iuk, new_rescue_code, settings.log_n, rescue_duration_ms, now_ms: now_ms) do |a, b|
        progress&.call("rescue", a, b)
      end
      edition = [self.edition + 1, 0xFFFF].min
      @type1 = type1
      @type2 = type2
      @type3 = Type3Block.encrypt(new_identity.previous_iuks, new_identity.imk, edition)
      new_identity
    end

    def ==(other)
      other.is_a?(S4Identity) && to_bytes == other.to_bytes
    end
    alias eql? ==

    def hash
      to_bytes.hash
    end

    def inspect
      "#<SQRL::S4Identity type1=#{!@type1.nil?} type2=#{!@type2.nil?} edition=#{edition} unknown=#{@unknown.length}>"
    end
  end
end
