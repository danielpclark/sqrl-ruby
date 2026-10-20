# frozen_string_literal: true

require "omniauth"
require "sqrl/core"
require "sqrl/rack"

# OmniAuth namespace, reopened to add the SQRL strategy.
module OmniAuth
  # OmniAuth strategy for SQRL login. See {OmniAuth::Strategies::SQRL}.
  module SQRL
    # Same as SQRL::VERSION; the gems release in lockstep.
    VERSION = ::SQRL::VERSION
  end
end

require_relative "strategies/sqrl"

OmniAuth.config.add_camelization "sqrl", "SQRL"
