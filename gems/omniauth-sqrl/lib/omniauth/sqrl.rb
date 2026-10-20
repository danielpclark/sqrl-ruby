# frozen_string_literal: true

require "omniauth"
require "sqrl/core"
require "sqrl/rack"

module OmniAuth
  # OmniAuth strategy for SQRL login. See {OmniAuth::Strategies::SQRL}.
  module SQRL
    VERSION = ::SQRL::VERSION
  end
end

require_relative "strategies/sqrl"

OmniAuth.config.add_camelization "sqrl", "SQRL"
