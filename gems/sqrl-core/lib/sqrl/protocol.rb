# frozen_string_literal: true

module SQRL
  # The SQRL client <-> server wire protocol: shared types and parsing.
  #
  # A transaction is a sequence of HTTPS POSTs. Every POST body is
  # +client=<b64u>&server=<b64u>&ids=<b64u>[&pids=<b64u>][&urs=<b64u>]+ where
  #
  # * +client+ is a CRLF-separated list of +name=value+ pairs (+ver+, +cmd+, +idk+, ...),
  # * +server+ is, for the first request, the complete +sqrl://+ URL as received, and for
  #   every following request the server's previous response *verbatim*,
  # * +ids+ is the Ed25519 signature (per-site identity key) over the concatenation of the
  #   +client+ and +server+ base64url strings; +pids+ the same with a previous identity key;
  #   +urs+ the same with the Unlock Request Signing Key.
  #
  # The server answers with a base64url-encoded CRLF list containing at least +ver+, +nut+,
  # +tif+ (hex transaction information flags) and +qry+ (the path to POST the next request
  # to).
  module Protocol
    # Protocol version this implementation speaks.
    VERSION = 1

    module_function

    # Parse a CRLF-separated +name=value+ list (LF-only input is tolerated).
    #
    # @return [Array<Array(String, String)>] pairs in order
    def parse_pairs(text)
      text.to_s.split("\r\n").flat_map { |l| l.split("\n") }.filter_map do |line|
        next if line.strip.empty?

        k, v = line.split("=", 2)
        v ? [k.strip, v.chomp("\r")] : [line.strip, ""]
      end
    end

    # Whether a +ver=+ value (e.g. +1+, +1,2+, +1-3,5+) includes a given version.
    def version_supported?(ver, wanted = VERSION)
      ver.to_s.split(",").any? do |part|
        part = part.strip
        if part.include?("-")
          a, b = part.split("-", 2).map(&:strip)
          a.match?(/\A\d+\z/) && b.match?(/\A\d+\z/) && a.to_i <= wanted && wanted <= b.to_i
        else
          part.match?(/\A\d+\z/) && part.to_i == wanted
        end
      end
    end

    # Decode a base64url text parameter into a UTF-8 string.
    def decode_text(b64)
      text = Util.b64u_decode(b64).force_encoding(Encoding::UTF_8)
      raise FormatError, "text is not UTF-8" unless text.valid_encoding?

      text
    end
  end

  # Transaction Information Flags returned by the server. Immutable value object.
  class Tif
    # The current identity (+idk+) is known to the server.
    ID_MATCH = 0x01
    # The previous identity (+pidk+) is known to the server.
    PREVIOUS_ID_MATCH = 0x02
    # The IP of this request matches the IP that requested the nut.
    IPS_MATCHED = 0x04
    # The account has SQRL authentication disabled.
    SQRL_DISABLED = 0x08
    # The server does not support the requested command / function.
    FUNCTION_NOT_SUPPORTED = 0x10
    # Transient error (e.g. stale nut): the client may retry with the new nut.
    TRANSIENT_ERROR = 0x20
    # The command could not be executed.
    COMMAND_FAILED = 0x40
    # The request was malformed or failed verification.
    CLIENT_FAILURE = 0x80
    # The identity does not match the one that started this transaction.
    BAD_ID_ASSOCIATION = 0x100
    # The identity has been superseded by a newer (re-keyed) identity.
    IDENTITY_SUPERSEDED = 0x200
    # Every bit defined by protocol version 1. "All SQRL clients MUST immediately terminate
    # any connection and abort any authentication operation with any SQRL server which
    # includes TIF bits not defined" (On The Wire, tif).
    DEFINED_BITS = 0x3FF
    ERROR_BITS = FUNCTION_NOT_SUPPORTED | TRANSIENT_ERROR | COMMAND_FAILED | CLIENT_FAILURE |
                 BAD_ID_ASSOCIATION | IDENTITY_SUPERSEDED

    attr_reader :value

    def initialize(value = 0)
      @value = Integer(value)
      freeze
    end

    # Parse the hexadecimal +tif=+ value.
    #
    # @raise [FormatError]
    def self.parse(hex)
      str = hex.to_s.strip
      raise FormatError, "invalid tif '#{hex}'" unless str.match?(/\A[0-9a-fA-F]+\z/)

      new(str.hex)
    end

    def self.[](value)
      value.is_a?(Tif) ? value : new(value)
    end

    # Whether only version-1 bits are set.
    def defined?
      @value.nobits?(~DEFINED_BITS)
    end

    # Test one or more flags.
    def has?(flag)
      @value.anybits?(flag)
    end

    def id_match? = has?(ID_MATCH)
    def previous_id_match? = has?(PREVIOUS_ID_MATCH)
    def ips_matched? = has?(IPS_MATCHED)
    def sqrl_disabled? = has?(SQRL_DISABLED)
    def function_not_supported? = has?(FUNCTION_NOT_SUPPORTED)
    def transient_error? = has?(TRANSIENT_ERROR)
    def command_failed? = has?(COMMAND_FAILED)
    def client_failure? = has?(CLIENT_FAILURE)
    def bad_id_association? = has?(BAD_ID_ASSOCIATION)
    def identity_superseded? = has?(IDENTITY_SUPERSEDED)

    # Any of the error flags.
    def error?
      has?(ERROR_BITS)
    end

    # Lower-case hex as sent on the wire.
    def to_hex
      @value.to_s(16)
    end

    def |(other)
      Tif.new(@value | Tif[other].value)
    end

    def &(other)
      Tif.new(@value & Tif[other].value)
    end

    # Clear the given bits.
    def without(flag)
      Tif.new(@value & ~flag)
    end

    def to_i
      @value
    end

    def ==(other)
      other.is_a?(Tif) ? other.value == @value : other == @value
    end
    alias eql? ==

    def hash
      @value.hash
    end

    def inspect
      "#<SQRL::Tif 0x#{to_hex}>"
    end
    alias to_s to_hex
  end

  # Client commands.
  module Command
    QUERY = :query
    IDENT = :ident
    DISABLE = :disable
    ENABLE = :enable
    REMOVE = :remove
    ALL = [QUERY, IDENT, DISABLE, ENABLE, REMOVE].freeze

    module_function

    # Parse the wire name; returns nil for anything unknown.
    def parse(str)
      sym = str.to_s.to_sym
      ALL.include?(sym) ? sym : nil
    end

    # The wire name.
    def to_wire(command)
      raise ArgumentError, "unknown command #{command.inspect}" unless ALL.include?(command)

      command.to_s
    end
  end

  # Client +opt=+ flags.
  class ClientOptions
    FLAGS = %i[sqrlonly hardlock cps suk noiptest].freeze

    # Request that the site disable all non-SQRL authentication.
    attr_accessor :sqrlonly
    # Request that the site disable all non-SQRL account recovery.
    attr_accessor :hardlock
    # The client can perform Client Provided Session redirection (+url=+ expected).
    attr_accessor :cps
    # Ask the server to return the account's SUK (needed before enable/remove).
    attr_accessor :suk
    # Do not require the request IP to match the nut's IP.
    attr_accessor :noiptest

    def initialize(sqrlonly: false, hardlock: false, cps: false, suk: false, noiptest: false)
      @sqrlonly = sqrlonly
      @hardlock = hardlock
      @cps = cps
      @suk = suk
      @noiptest = noiptest
    end

    alias sqrlonly? sqrlonly
    alias hardlock? hardlock
    alias cps? cps
    alias suk? suk
    alias noiptest? noiptest

    # Parse an +opt=+ value.
    def self.from_wire(str)
      o = new
      str.to_s.split("~").each do |part|
        flag = part.strip
        o.public_send("#{flag}=", true) if FLAGS.include?(flag.to_sym)
      end
      o
    end

    # Render the +opt=+ value (+~+ separated), or nil when no option is set.
    def to_wire
      set = FLAGS.select { |f| public_send(f) }
      set.empty? ? nil : set.join("~")
    end

    def dup
      ClientOptions.new(**to_h)
    end

    def to_h
      FLAGS.to_h { |f| [f, public_send(f) ? true : false] }
    end

    def ==(other)
      other.is_a?(ClientOptions) && other.to_h == to_h
    end
    alias eql? ==

    def hash
      to_h.hash
    end

    def inspect
      "#<SQRL::ClientOptions #{to_wire || "(none)"}>"
    end
  end

  # One button of a server +ask=+.
  AskButton = Struct.new(:label, :url, keyword_init: true) do
    def initialize(label:, url: nil)
      super
    end
  end

  # A server question (+ask=<msg>~<button1>[;url]~<button2>[;url]+, each part base64url).
  class Ask
    # The question text.
    attr_reader :message
    # Zero, one or two buttons. A client shows "OK" when there are none.
    attr_reader :buttons
    # Button numbers (1 or 2; 0 is the plain "OK" of a buttonless ask) whose answer lets
    # the transaction proceed, or nil to accept any answer. A server-side setting only:
    # it is not part of the wire form.
    attr_reader :accept

    def initialize(message:, buttons: [], accept: nil)
      @message = message.to_s
      @buttons = buttons.map { |b| b.is_a?(AskButton) ? b : AskButton.new(**b) }.freeze
      @accept = accept.nil? ? nil : Array(accept).map(&:to_i).freeze
      freeze
    end

    # Whether a +btn=+ answer lets the login proceed. Any answer does when +accept+ is nil.
    def accepts?(btn)
      return true if @accept.nil?

      @accept.include?(btn.to_i)
    end

    # Parse the wire form.
    #
    # @raise [FormatError]
    def self.parse(value)
      parts = value.to_s.split("~", -1)
      message = Protocol.decode_text(parts.shift || "")
      buttons = parts.first(2).map do |p|
        label_b64, url = p.split(";", 2)
        AskButton.new(label: Protocol.decode_text(label_b64 || ""), url: url)
      end
      new(message: message, buttons: buttons)
    end

    # Render the wire form.
    def to_wire
      s = Util.b64u_encode(@message.b)
      @buttons.each do |b|
        s += "~#{Util.b64u_encode(b.label.to_s.b)}"
        s += ";#{b.url}" if b.url
      end
      s
    end

    def ==(other)
      other.is_a?(Ask) && other.message == @message && other.buttons == @buttons && other.accept == @accept
    end
    alias eql? ==

    def hash
      [@message, @buttons, @accept].hash
    end
  end

  # A parsed server response.
  class ServerResponse
    # The response exactly as received (whitespace removed): what the next request's
    # +server=+ parameter carries.
    attr_reader :raw
    # All +name=value+ pairs in order.
    attr_reader :params
    attr_reader :ver, :nut, :tif, :qry, :url, :sin, :suk, :ask, :can

    # Parse a base64url response body.
    #
    # @raise [ProtocolError, FormatError]
    def self.parse(body)
      new(body)
    end

    def initialize(body)
      @raw = body.to_s.delete(" \t\r\n\f\v")
      raise ProtocolError, "empty server response" if @raw.empty?

      decoded = Util.b64u_decode(@raw).force_encoding(Encoding::UTF_8)
      raise ProtocolError, "server response is not UTF-8" unless decoded.valid_encoding?

      @params = Protocol.parse_pairs(decoded).freeze
      @ver = fetch("ver") or raise ProtocolError, "response lacks ver"
      unless Protocol.version_supported?(@ver, Protocol::VERSION)
        raise ProtocolError, "server speaks version #{@ver}, not #{Protocol::VERSION}"
      end

      @nut = fetch("nut") or raise ProtocolError, "response lacks nut"
      raise ProtocolError, "response has an empty nut" if @nut.empty?

      @tif = Tif.parse(fetch("tif") || raise(ProtocolError, "response lacks tif"))
      unless @tif.defined?
        raise ProtocolError, "server returned undefined TIF bits (#{@tif.to_hex}); aborting"
      end

      @qry = fetch("qry") or raise ProtocolError, "response lacks qry"
      suk = fetch("suk")
      @suk = suk && !suk.empty? ? Util.b64u_decode_fixed(suk, 32) : nil
      ask = fetch("ask")
      @ask = ask && !ask.empty? ? Ask.parse(ask) : nil
      @url = presence(fetch("url"))
      @sin = presence(fetch("sin"))
      @can = presence(fetch("can"))
      freeze
    end

    # Value of an arbitrary parameter, or nil.
    def [](name)
      fetch(name.to_s)
    end

    def ==(other)
      other.is_a?(ServerResponse) && other.raw == @raw
    end
    alias eql? ==

    def hash
      @raw.hash
    end

    def inspect
      "#<SQRL::ServerResponse tif=0x#{@tif.to_hex} nut=#{@nut} qry=#{@qry}>"
    end

    private

    def fetch(name)
      pair = @params.find { |(k, _)| k == name }
      pair && pair[1]
    end

    def presence(value)
      value.nil? || value.empty? ? nil : value
    end
  end
end
