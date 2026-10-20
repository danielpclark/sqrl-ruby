# frozen_string_literal: true

module SQRL
  # A parsed +sqrl://+ URL.
  #
  # * The *site key* that all per-site keys are derived from is the lower-cased host name
  #   (user info and port stripped). When the URL carries an +x=N+ parameter, the first +N+
  #   characters of the path (including the leading +/+) are appended.
  # * The *POST URL* is the same URL with the scheme replaced by +https+ (+qrl://+, the
  #   legacy plain-http scheme, is only accepted for loopback hosts, for development).
  # * +can=+ carries a base64url-encoded URL to send the browser to if the user cancels.
  class URL
    # The URL exactly as received (this is what the first +server=+ parameter carries).
    attr_reader :original
    # +sqrl+ or +qrl+ (lower-cased).
    attr_reader :scheme
    # +host[:port]+ without user info, as used for the POST URL.
    attr_reader :authority
    # Lower-cased host name.
    attr_reader :host
    # Explicit port, if any.
    attr_reader :port
    # The path (starts with +/+; +/+ if absent).
    attr_reader :path
    # The raw query string without the leading +?+.
    attr_reader :query
    # The +nut=+ value, if any.
    attr_reader :nut
    # Value of +x=+ (path characters included in the site key).
    attr_reader :path_extension
    # Decoded +can=+ cancel URL (relative URLs are resolved against the site).
    attr_reader :cancel_url
    # Site key string used for key derivation.
    attr_reader :site_key

    LOOPBACK_HOSTS = %w[localhost 127.0.0.1 [::1]].freeze

    # Parse a +sqrl://+ (or loopback-only +qrl://+) URL.
    #
    # @param input [String]
    # @return [URL]
    # @raise [FormatError]
    def self.parse(input)
      new(input)
    end

    # Split a query string into +[key, value]+ pairs. Values are percent-decoded only for
    # the characters SQRL servers may legitimately escape; the +nut+ is otherwise used
    # verbatim.
    #
    # @param query [String]
    # @return [Array<Array(String, String)>]
    def self.query_pairs(query)
      query.to_s.split("&").reject(&:empty?).map do |kv|
        k, v = kv.split("=", 2)
        [k, v ? percent_decode(v) : ""]
      end
    end

    # Percent-decode a string, leaving malformed escapes untouched.
    def self.percent_decode(str)
      return str unless str.include?("%")

      str.gsub(/%([0-9A-Fa-f]{2})/) { Regexp.last_match(1).hex.chr }
         .force_encoding(Encoding::UTF_8)
         .scrub
    end

    def self.loopback?(host)
      LOOPBACK_HOSTS.include?(host) || host.end_with?(".localhost")
    end

    # Split +host[:port]+ handling IPv6 literals. Returns +[host, port_or_nil]+.
    def self.split_host_port(hostport)
      if hostport.start_with?("[")
        close = hostport.index("]")
        raise FormatError, "unterminated IPv6 literal" unless close

        host = hostport[0..close]
        after = hostport[(close + 1)..]
        return [host, nil] if after.empty?
        raise FormatError, "invalid port" unless after.start_with?(":") && after[1..].match?(/\A\d+\z/)

        return [host, parse_port(after[1..])]
      end
      host, port = hostport.rpartition(":").then { |h, sep, p| sep.empty? ? [hostport, nil] : [h, p] }
      return [host, nil] if port.nil?
      raise FormatError, "invalid port" unless port.match?(/\A\d+\z/)

      [host, parse_port(port)]
    end

    def self.parse_port(str)
      port = Integer(str, 10)
      raise FormatError, "invalid port" unless port.between?(0, 65_535)

      port
    end

    def initialize(input)
      raise FormatError, "not a URL" unless input.is_a?(String)

      @original = input.strip
      scheme, rest = @original.split("://", 2)
      raise FormatError, "not a URL" unless rest

      @scheme = scheme.downcase
      raise FormatError, "unsupported scheme '#{@scheme}'" unless %w[sqrl qrl].include?(@scheme)

      rest = rest.split("#", 2).first || ""
      end_of_authority = rest.index(%r{[/?]}) || rest.length
      authority_raw = rest[0...end_of_authority]
      path_and_query = rest[end_of_authority..] || ""
      path, query = path_and_query.split("?", 2)
      @path = path.nil? || path.empty? ? "/" : path
      @query = query || ""

      hostport = authority_raw.include?("@") ? authority_raw.rpartition("@").last : authority_raw
      host, @port = self.class.split_host_port(hostport)
      raise FormatError, "missing host" if host.empty?

      @host = host.downcase
      raise FormatError, "invalid host" if @host.match?(%r{[\s/\\]})

      @authority = @port ? "#{@host}:#{@port}" : @host
      if @scheme == "qrl" && !self.class.loopback?(@host)
        raise FormatError, "plain-http qrl:// URLs are only allowed for localhost"
      end

      @nut = nil
      @path_extension = 0
      cancel = nil
      self.class.query_pairs(@query).each do |k, v|
        case k
        when "nut" then @nut = v
        when "x", "X"
          # GRC's client treats x= and X= identically and parses the value with an
          # "intolerant" converter that stops at the first non-digit.
          digits = v[/\A\d*/]
          @path_extension = digits.empty? ? 0 : digits.to_i
        when "can"
          bytes = Util.b64u_decode(v)
          cancel = bytes.force_encoding(Encoding::UTF_8)
          raise FormatError, "can= is not UTF-8" unless cancel.valid_encoding?
        end
      end

      @site_key = @host.dup
      if @path_extension.positive?
        take = [@path_extension, @path.bytesize].min
        # never cut in the middle of a multi-byte character
        take -= 1 until @path.byteslice(0, take).force_encoding(Encoding::UTF_8).valid_encoding?
        @site_key << @path.byteslice(0, take).force_encoding(Encoding::UTF_8)
      end
      @site_key.freeze
      @cancel_url = cancel && resolve(cancel)
      freeze
    end

    # +https+ (or +http+ for +qrl://+).
    def http_scheme
      @scheme == "qrl" ? "http" : "https"
    end

    # +https://authority+
    def origin
      "#{http_scheme}://#{@authority}"
    end

    # The URL to POST the first (query) request to.
    def post_url
      @query.empty? ? "#{origin}#{@path}" : "#{origin}#{@path}?#{@query}"
    end

    # The URL to POST a follow-up request to, from the server's +qry=+ value.
    #
    # +qry+ must be a path on the same host (it starts with +/+); absolute URLs pointing
    # elsewhere are rejected to stop a compromised response redirecting signatures.
    #
    # @raise [ProtocolError]
    def post_url_for_qry(qry)
      qry = qry.to_s.strip
      unless qry.start_with?("/") && !qry.start_with?("//")
        raise ProtocolError, "qry must be a server-relative path, got '#{qry}'"
      end

      "#{origin}#{qry}"
    end

    # Site key bytes, optionally extended with an Alt-ID (+site_key || 0x00 || alt_id+).
    #
    # @return [String] binary
    def site_key_bytes(alt_id = nil)
      bytes = @site_key.b
      alt = alt_id.to_s.strip
      bytes << "\0" << alt.b unless alt.empty?
      bytes
    end

    # Resolve a possibly-relative URL (from +can=+ or +url=+) against this site.
    def resolve(target)
      t = target.to_s.strip
      if t.start_with?("https://", "http://")
        t
      elsif t.start_with?("/")
        "#{origin}#{t}"
      else
        "#{origin}/#{t}"
      end
    end

    # Whether an absolute URL (e.g. the CPS +url=+) points at this site's host, using the
    # site's own HTTP scheme (https for sqrl://, http only for loopback qrl:// sites), so
    # a reply cannot downgrade the browser to plain http.
    def same_host?(target)
      t = target.to_s.strip
      scheme, rest = t.split("://", 2)
      return false unless rest && scheme.casecmp?(http_scheme)

      stop = rest.index(%r{[/?#]}) || rest.length
      hostport = rest[0...stop]
      hostport = hostport.rpartition("@").last if hostport.include?("@")
      host, = self.class.split_host_port(hostport)
      host.casecmp?(@host)
    rescue FormatError
      false
    end

    def to_s
      @original
    end

    def ==(other)
      other.is_a?(URL) && other.original == @original
    end
    alias eql? ==

    def hash
      @original.hash
    end

    def inspect
      "#<SQRL::URL #{@original}>"
    end
  end
end
