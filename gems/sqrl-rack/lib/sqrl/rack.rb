# frozen_string_literal: true

require "rack"
require "sqrl/core"

module SQRL
  # SQRL login for Rack applications: the framework-neutral {Endpoint}, the {Middleware}
  # that mounts it, the per-request {Facade} for applications, the login markup
  # ({LoginBlock}), QR rendering ({QR}) and the browser script ({Assets}).
  module Rack
    # Same as SQRL::VERSION; the gems release in lockstep.
    VERSION = SQRL::VERSION

    # Raised for configuration problems (for example a missing session middleware).
    class Error < SQRL::Error; end
  end
end

require_relative "rack/host_resolver"
require_relative "rack/assets"
require_relative "rack/qr"
require_relative "rack/login_block"
require_relative "rack/endpoint"
require_relative "rack/facade"
require_relative "rack/middleware"
