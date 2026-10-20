# frozen_string_literal: true

require_relative "sqrl/version"
require_relative "sqrl/errors"
require_relative "sqrl/util"
require_relative "sqrl/crypto"
require_relative "sqrl/identity"

# SQRL (Secure Quick Reliable Login) for Ruby.
module SQRL
  autoload :Storage, "sqrl/storage"
  autoload :S4Identity, "sqrl/storage"
  autoload :Textual, "sqrl/textual"
  autoload :URL, "sqrl/url"
  autoload :Protocol, "sqrl/protocol"
  autoload :Tif, "sqrl/protocol"
  autoload :Command, "sqrl/protocol"
  autoload :ClientOptions, "sqrl/protocol"
  autoload :Ask, "sqrl/protocol"
  autoload :ServerResponse, "sqrl/protocol"
  autoload :Session, "sqrl/protocol/session"
  autoload :Server, "sqrl/server"
  autoload :TestVectors, "sqrl/test_vectors"
end
