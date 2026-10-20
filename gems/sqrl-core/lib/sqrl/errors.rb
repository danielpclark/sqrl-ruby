# frozen_string_literal: true

module SQRL
  # Base class for every error raised by the SQRL gems.
  class Error < StandardError; end

  # Input could not be parsed (bad base64, bad header, bad length...).
  class FormatError < Error; end

  # A cryptographic check failed (bad password, bad rescue code, bad signature...).
  class CryptoError < Error; end

  # The protocol state does not permit the requested operation.
  class ProtocolError < Error; end
end
