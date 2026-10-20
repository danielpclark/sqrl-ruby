# frozen_string_literal: true

module SQRL
  module Client
    module Conformance
      # How the runner finds its way around the site under test. The default works for any
      # page the {Discovery} module understands; subclass or pass your own object
      # responding to +login_page(transport)+ for sites with a different layout (the
      # interop suite does this for the Rust reference server).
      class Site
        # What a login page gives us.
        Page = Struct.new(:sqrl_url, :status_url, :page_url, :html, keyword_init: true)

        attr_reader :login_url

        # @param login_url [String]
        # @param success_matcher [#call, nil] +(Transport::Response, Page) -> Boolean+
        #   deciding whether a landing response means "logged in"; defaults to a 2xx
        #   response whose final URL is not the login page
        def initialize(login_url:, success_matcher: nil)
          @login_url = login_url
          @success_matcher = success_matcher
        end

        # Fetch the login page with +transport+ (so its cookies become the "browser").
        #
        # @return [Page]
        def login_page(transport)
          response = transport.get(@login_url)
          unless response.success?
            raise TransportError.new("login page answered #{response.status}", url: @login_url, status: response.status)
          end

          found = Discovery.find(response.body, base_url: response.final_url)
          Page.new(sqrl_url: found.sqrl_url, status_url: found.status_url, page_url: response.final_url, html: response.body)
        end

        # Whether +response+ (after following the CPS URL or the poll's +next+) shows a
        # logged-in session.
        def success?(response, page = nil)
          return @success_matcher.call(response, page) if @success_matcher
          return false if response.nil? || !response.success?

          strip = ->(u) { u.to_s.sub(/[?#].*\z/, "").chomp("/") }
          strip.call(response.final_url) != strip.call(@login_url)
        end

        # The CPS callback path without its token, for the "callback without token" case.
        def callback_without_token(cps_url)
          cps_url.sub(/\?.*\z/, "")
        end
      end
    end
  end
end
