# frozen_string_literal: true

require "sqrl/core"
require_relative "client/errors"
require_relative "client/identity"
require_relative "client/transport"
require_relative "client/discovery"
require_relative "client/agent"

# SQRL namespace, reopened for the client.
module SQRL
  # A bot-capable SQRL client: everything a script, a test suite or an automated service
  # needs to log in to a SQRL-enabled website without a browser or a human.
  #
  #   identity = SQRL::Client::Identity.load("bot.sqrl", password: ENV["SQRL_PASSWORD"])
  #   agent    = SQRL::Client::Agent.new(identity: identity)
  #   result   = agent.login("https://example.com/login")
  #   result.authenticated?  # => true
  #   agent.http.get("https://example.com/account")  # carries the logged-in cookies
  module Client
    autoload :Capybara, "sqrl/client/capybara"
    autoload :Conformance, "sqrl/client/conformance"
    autoload :CLI, "sqrl/client/cli"

    # Version of the client gem (released in lockstep with sqrl-core).
    VERSION = SQRL::VERSION
  end
end
