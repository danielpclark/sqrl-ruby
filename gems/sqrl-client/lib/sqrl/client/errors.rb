# frozen_string_literal: true

module SQRL
  module Client
    # Base class of every error raised by the client gem.
    class Error < SQRL::Error; end

    # No SQRL login URL could be found for the target.
    class DiscoveryError < Error; end

    # The server posed an +ask=+ question and no +ask_handler+ was configured to answer it.
    class AskRequired < Error
      # @return [SQRL::Ask]
      attr_reader :ask

      def initialize(ask)
        @ask = ask
        super("the server asks: #{ask.message.inspect} (buttons: #{ask.buttons.map(&:label).inspect}); " \
              "configure an ask_handler to answer it")
      end
    end

    # The transaction ended without the requested outcome. +tif+ is the last TIF received,
    # +reason+ a Symbol such as +:disabled+, +:superseded+, +:unknown_site+, +:ip_mismatch+,
    # +:command_failed+ or +:transient+.
    class LoginFailed < Error
      attr_reader :tif, :reason, :state, :result

      def initialize(message, reason:, tif: nil, state: nil, result: nil)
        @reason = reason
        @tif = tif
        @state = state
        @result = result
        super(message)
      end
    end

    # The HTTP layer failed (connection refused, TLS error, timeout, non-2xx SQRL endpoint).
    class TransportError < Error
      attr_reader :url, :status

      def initialize(message, url: nil, status: nil)
        @url = url
        @status = status
        super(message)
      end
    end

    # An operation needs the Identity Unlock Key (rescue code) and it is not available.
    class IdentityLocked < Error; end
  end
end
