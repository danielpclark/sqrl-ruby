# frozen_string_literal: true

module SQRL
  module Rails
    # Base controller of the engine. Deliberately not derived from the host's
    # +ApplicationController+, so host filters (authentication, browser checks) do not
    # apply to the protocol endpoints.
    class ApplicationController < ::ActionController::Base
      protect_from_forgery with: :exception

      # A before_issue / before_handle hook refused the request.
      rescue_from SQRL::Server::RateLimited do |error|
        render_rack(sqrl_endpoint.rate_limited(error, json: request.format.json?))
      end

      # The request host may not be used to issue SQRL URLs (allowed_hosts, host cache
      # limit).
      rescue_from SQRL::Rack::HostNotAllowed do |error|
        render plain: error.message, status: :bad_request
      end

      private

      def sqrl_endpoint
        @sqrl_endpoint ||= SQRL::Rails.endpoint_for(request)
      end

      def sqrl_config
        SQRL::Rails.config
      end

      # The host application's URL prefix (its relative URL root), without the engine
      # mount the current request came in through.
      def host_script_name
        name = request.script_name.to_s
        mount = SQRL::Rails.mount_path
        name.end_with?(mount) ? name[0, name.length - mount.length] : name
      end

      # Public path of an engine route (+:login+, +:status+, ...).
      def engine_path(name)
        SQRL::Rails.path_for(name, script_name: host_script_name)
      end

      def render_rack(triple)
        status, headers, body = triple
        headers.each { |k, v| response.set_header(k, v) }
        render body: body.join, status: status, content_type: headers["content-type"]
      end

      # The host's Authentication concern uses the host's route helpers (root_url,
      # new_session_path); resolve them through the main_app proxy.
      def method_missing(name, ...)
        if host_route_helper?(name)
          main_app.public_send(name, ...)
        else
          super
        end
      end

      def respond_to_missing?(name, include_private = false)
        host_route_helper?(name) || super
      end

      def host_route_helper?(name)
        name.to_s.match?(/_(url|path)\z/) && respond_to?(:main_app) && main_app.respond_to?(name)
      end
    end
  end
end
