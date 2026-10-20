# frozen_string_literal: true

module SQRL
  module Client
    # Drives a Capybara session through a SQRL login, the way a native client on the same
    # machine would: the protocol runs out of band with an {Agent}, then the *browser*
    # visits the server's CPS +url=+, so the browser's own session cookie is the one that
    # gets logged in.
    #
    #   visit "/login"
    #   SQRL::Client::Capybara.login(page, identity: SQRL::Client::Identity.ephemeral("bot"))
    #   expect(page).to have_content("Welcome")
    module Capybara
      module_function

      # @param page [Capybara::Session] showing a page with a SQRL login link
      # @param identity [Identity]
      # @param cps [Boolean] +true+: visit the CPS URL in the browser; +false+: perform
      #   +ident+ only and wait for the page's own poller to navigate
      # @param wait [Numeric] seconds to wait for the non-CPS redirect
      # @param agent_opts [Hash] passed to {Agent#initialize}
      # @return [LoginResult]
      def login(page, identity:, cps: true, wait: 10, **agent_opts)
        found = Discovery.find(page.html, base_url: page.current_url)
        agent = Agent.new(identity: identity, cps: cps, follow_cps: false, poll: false, **agent_opts)
        result = agent.login(found.sqrl_url)
        if cps
          raise LoginFailed.new("the server sent no CPS url=", reason: :no_cps, tif: result.tif) unless result.cps_url

          page.visit(result.cps_url)
        else
          start_path = page.current_path
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + wait
          sleep 0.1 while page.current_path == start_path && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
        end
        result
      end

      # Run +disable+/+enable+/+remove+ against the page's login link.
      def command(page, command, identity:, rescue_code: nil, **agent_opts)
        found = Discovery.find(page.html, base_url: page.current_url)
        agent = Agent.new(identity: identity, cps: false, poll: false, **agent_opts)
        case command
        when :disable then agent.disable(found.sqrl_url)
        when :enable then agent.enable(found.sqrl_url, rescue_code: rescue_code)
        when :remove then agent.remove(found.sqrl_url, rescue_code: rescue_code)
        else raise ArgumentError, "command must be :disable, :enable or :remove"
        end
      end
    end
  end
end
