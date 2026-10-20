# frozen_string_literal: true

module SQRL
  # Drives one SQRL transaction for one unlocked identity against one +sqrl://+ URL.
  #
  # The session builds signed {Request}s (+query+, +ident+, +disable+, +enable+, +remove+)
  # and consumes the server's responses with {#feed}. It performs no I/O itself: the caller
  # POSTs +request.body+ to +request.url+ with
  # +Content-Type: application/x-www-form-urlencoded+ and feeds the response body back.
  class Session
    # A request ready to be POSTed.
    Request = Struct.new(:url, :body, :command, :client_text, keyword_init: true) do
      def inspect
        "#<SQRL::Session::Request #{command} -> #{url}>"
      end
    end

    # High-level summary of where a transaction stands, derived from the last response.
    State = Struct.new(:kind, :disabled, :message, keyword_init: true) do
      def initialize(kind:, disabled: false, message: nil)
        super
      end

      %i[no_response unknown known previous_known transient superseded failed].each do |k|
        define_method(:"#{k}?") { kind == k }
      end

      def disabled? = disabled ? true : false

      def ==(other)
        case other
        when Symbol then kind == other
        when State then to_h == other.to_h
        else false
        end
      end

      def inspect
        extra = disabled ? " disabled" : ""
        extra += " (#{message})" if message
        "#<SQRL::Session::State #{kind}#{extra}>"
      end
    end

    attr_reader :url, :last_command

    # @param identity [UnlockedIdentity]
    # @param url [URL]
    # @param options [ClientOptions]
    # @param alt_id [String, nil] the optional "Alt-ID" selecting a different identity for
    #   the same site
    # @param lock_factory [#call, nil] overrides SUK/VUK generation (tests only); receives
    #   the ILK and returns an {Identity::ServerLock}
    def initialize(identity, url, options: ClientOptions.new, alt_id: nil, lock_factory: nil)
      raise ArgumentError, "identity must be an UnlockedIdentity" unless identity.is_a?(UnlockedIdentity)

      url = URL.parse(url) unless url.is_a?(URL)
      @identity = identity
      @url = url
      @site_key = url.site_key_bytes(alt_id).freeze
      @options = options.dup
      @lock_factory = lock_factory || ->(ilk) { Identity.make_server_lock(ilk) }
      @prev_index = 0
      @last = nil
      @last_command = nil
      @pending_btn = nil
      @answered_ask = false
      @last_lock = nil
    end

    # Options in use (a copy; use {#options=} to change them).
    def options
      @options.dup
    end

    # Change options for subsequent requests.
    def options=(options)
      @options = options.dup
    end

    # The most recent server response, if any.
    def last_response
      @last
    end

    # Per-site public key (+idk+) of the current identity, as raw bytes.
    def idk
      @identity.site_public_key(@site_key)
    end

    # +idk+ as base64url, the form it has on the wire.
    def idk_b64
      Util.b64u_encode(idk)
    end

    # Whether the identity has any previous identities to offer as +pidk+.
    def has_previous?
      @identity.previous_count.positive?
    end

    def previous_count
      @identity.previous_count
    end

    # Index of the previous identity currently offered as +pidk+.
    attr_reader :prev_index
    alias previous_index prev_index

    # Move on to the next older previous identity. Returns false when none remain.
    def try_next_previous
      return false unless @prev_index + 1 < @identity.previous_count

      @prev_index += 1
      true
    end

    # Record the user's answer to the server's +ask=+: 0 for the plain "OK" (shown when the
    # ask carries no buttons), 1 or 2 for the first or second button. Cancelling the ask
    # means not sending any further command at all, so there is no value for it.
    def set_button(btn)
      @pending_btn = btn.to_i.clamp(0, 2)
      @answered_ask = true
    end

    # The server's pending question, if the last response carried one and it has not been
    # answered yet. Per the specification an +ask=+ is only honoured in the reply to a
    # +query+ whose TIF has the current-ID-match bit set; anywhere else it is ignored.
    def pending_ask
      return nil if @answered_ask || @last_command != Command::QUERY
      return nil unless @last
      return nil if !@last.tif.id_match? || @last.tif.command_failed?

      @last.ask
    end

    # The URL bound to ask button +index+ (0-based), if the server attached one. The server
    # may only supply a root-anchored path; it is forced to start with +/+ and is resolved
    # against this site's scheme, host and port, so it can never point elsewhere.
    def ask_button_url(index)
      ask = @last&.ask
      raw = ask&.buttons&.[](index)&.url&.strip
      return nil if raw.nil? || raw.empty?

      "#{@url.origin}/#{raw.sub(%r{\A/+}, "")}"
    end

    # Summary of the last response.
    #
    # @return [State]
    def state
      return State.new(kind: :no_response) unless @last

      t = @last.tif
      return State.new(kind: :superseded) if t.identity_superseded?
      return State.new(kind: :transient) if t.transient_error?
      if t.client_failure?
        return State.new(kind: :failed, message: "the server rejected the request (client failure)")
      end
      if t.bad_id_association?
        return State.new(kind: :failed, message: "identity does not match the one that started this session")
      end
      if t.function_not_supported?
        return State.new(kind: :failed, message: "the server does not support that command")
      end

      if t.command_failed?
        if t.value == Tif::COMMAND_FAILED
          return State.new(kind: :failed,
                           message: "the server refused the request, most likely because this connection's " \
                                    "IP address differs from the one that requested the login page")
        end
        return State.new(kind: :failed, message: "the server could not perform the command")
      end
      if t.id_match?
        State.new(kind: :known, disabled: t.sqrl_disabled?)
      elsif t.previous_id_match?
        State.new(kind: :previous_known, disabled: t.sqrl_disabled?)
      else
        State.new(kind: :unknown)
      end
    end

    # The CPS success URL from the last response, validated to point at this site.
    #
    # @return [String, nil]
    # @raise [ProtocolError] when +url=+ points elsewhere
    def cps_url
      u = @last&.url
      return nil unless u

      resolved = @url.resolve(u)
      raise ProtocolError, "CPS url '#{u}' does not point at #{@url.host}" unless @url.same_host?(resolved)

      resolved
    end

    # The cancel URL: the server's most recent +can=+ reply parameter (a plain URL or
    # root-relative path) if any, else the base64url-encoded +can=+ of the SQRL URL.
    #
    # A cancel URL that does not point at this site (another host, or plain http for a
    # sqrl:// site) is ignored and +nil+ is returned, so a tampered reply cannot send the
    # browser elsewhere.
    def cancel_url
      c = @last&.can
      resolved = c ? @url.resolve(c) : @url.cancel_url
      return nil unless resolved
      return resolved if @url.same_host?(resolved)

      nil
    end

    # Build the initial (or a repeated) +query+, offering the current previous identity.
    def query
      build(Command::QUERY, include_pidk: true)
    end

    # Build an +ident+: log in, create the account, or re-key it, depending on the last
    # query's answer.
    def ident
      require_response!("ident")
      if needs_rekey?
        lock, urs = rekey_material
        build(Command::IDENT, include_pidk: true, lock: lock, urs_seed: urs)
      elsif !last_tif.id_match?
        build(Command::IDENT, lock: @lock_factory.call(@identity.ilk))
      else
        build(Command::IDENT)
      end
    end

    # Build a +disable+.
    def disable
      require_response!("disable")
      if needs_rekey?
        lock, urs = rekey_material
        build(Command::DISABLE, include_pidk: true, lock: lock, urs_seed: urs)
      else
        build(Command::DISABLE)
      end
    end

    # Build an +enable+. +iuk+ is required unless only a previous identity matched.
    def enable(iuk = nil)
      require_response!("enable")
      lock, urs = unlock_material(iuk)
      build(Command::ENABLE, include_pidk: !lock.nil?, lock: lock, urs_seed: urs)
    end

    # Build a +remove+. +iuk+ is required unless only a previous identity matched.
    def remove(iuk = nil)
      require_response!("remove")
      lock, urs = unlock_material(iuk)
      build(Command::REMOVE, include_pidk: !lock.nil?, lock: lock, urs_seed: urs)
    end

    # Feed the body of the server's HTTP response. Validates it and makes it the basis of
    # the next request.
    #
    # @return [ServerResponse]
    # @raise [ProtocolError, FormatError]
    def feed(body)
      resp = ServerResponse.parse(body)
      # qry must stay on this host
      @url.post_url_for_qry(resp.qry)
      @answered_ask = false if resp.ask
      @last = resp
    end

    # Whether the last reply was the "exactly 0x40" a server returns when the query IP does
    # not match the IP that requested the SQRL URL and +noiptest+ was not offered.
    def ip_check_failed?
      !@last.nil? && @last.tif.value == Tif::COMMAND_FAILED
    end

    def inspect
      "#<SQRL::Session #{@url.host} state=#{state.kind}>"
    end

    private

    def require_response!(command)
      raise ProtocolError, "send a query before #{command}" if @last.nil?
    end

    def last_tif
      @last ? @last.tif : Tif.new(0)
    end

    # Whether the server's last answer says the account is still bound to the previous
    # identity (and must therefore be re-keyed by the next command).
    def needs_rekey?
      t = last_tif
      t.previous_id_match? && !t.id_match?
    end

    # Lock material and +urs+ seed for a re-key (previous identity matched).
    def rekey_material
      suk = @last&.suk
      raise ProtocolError, "server matched a previous identity but sent no suk" unless suk

      urs_seed = @identity.previous_unlock_request_seed(@prev_index, suk)
      raise ProtocolError, "no such previous identity" unless urs_seed

      [@lock_factory.call(@identity.ilk), urs_seed]
    end

    # +urs+ seed for +enable+/+remove+: the current IUK (from the rescue code) when the
    # current identity matched, or the previous IUK when only a previous identity matched.
    def unlock_material(iuk)
      return rekey_material if needs_rekey?

      suk = @last&.suk
      raise ProtocolError, "the server did not provide the account's suk" unless suk
      raise ProtocolError, "this operation needs the rescue code (IUK)" unless iuk

      [nil, Identity.unlock_request_seed(iuk, suk)]
    end

    def server_param
      @last ? @last.raw : Util.b64u_encode(@url.original.b)
    end

    def post_url
      @last ? @url.post_url_for_qry(@last.qry) : @url.post_url
    end

    # Build and sign a request.
    def build(command, include_pidk: false, lock: nil, urs_seed: nil)
      url = post_url
      server = server_param

      client = "ver=#{Protocol::VERSION}\r\n"
      client << "cmd=#{Command.to_wire(command)}\r\n"
      client << "idk=#{idk_b64}\r\n"
      pseed = nil
      if include_pidk && has_previous?
        pseed = @identity.previous_site_seed(@prev_index, @site_key)
        raise ProtocolError, "no such previous identity" unless pseed

        client << "pidk=#{Util.b64u_encode(Crypto.ed25519_public(pseed))}\r\n"
      end
      if lock
        client << "suk=#{Util.b64u_encode(lock.suk)}\r\n"
        client << "vuk=#{Util.b64u_encode(lock.vuk)}\r\n"
      end
      # The SUK is requested with every command (as GRC's reference client does) so that a
      # later enable/remove always has it. sqrlonly/hardlock only make sense while an
      # association exists, so they are never sent with remove.
      opts = @options.dup
      opts.suk = true
      if command == Command::REMOVE
        opts.sqrlonly = false
        opts.hardlock = false
      end
      opt = opts.to_wire
      client << "opt=#{opt}\r\n" if opt
      if @pending_btn
        client << "btn=#{@pending_btn}\r\n"
        @pending_btn = nil
      end
      if (sin = @last&.sin)
        seed = @identity.site_seed(@site_key)
        client << "ins=#{Util.b64u_encode(Identity.indexed_secret(seed, sin.b))}\r\n"
        client << "pins=#{Util.b64u_encode(Identity.indexed_secret(pseed, sin.b))}\r\n" if pseed
      end

      client_b64 = Util.b64u_encode(client.b)
      msg = (client_b64 + server).b

      ids = Crypto.ed25519_sign(@identity.site_seed(@site_key), msg)
      body = "client=#{client_b64}&server=#{server}&ids=#{Util.b64u_encode(ids)}"
      body << "&pids=#{Util.b64u_encode(Crypto.ed25519_sign(pseed, msg))}" if pseed
      body << "&urs=#{Util.b64u_encode(Crypto.ed25519_sign(urs_seed, msg))}" if urs_seed

      @last_lock = lock
      @last_command = command
      Request.new(url: url, body: body.freeze, command: command, client_text: client.freeze)
    end
  end
end
