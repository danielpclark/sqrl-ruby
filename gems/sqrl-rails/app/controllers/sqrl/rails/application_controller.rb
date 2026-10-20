# frozen_string_literal: true

module SQRL
  module Rails
    # Base controller of the engine. Deliberately not derived from the host's
    # +ApplicationController+, so host filters (authentication, browser checks) do not
    # apply to the protocol endpoints.
    class ApplicationController < ::ActionController::Base
      protect_from_forgery with: :exception

      private

      def sqrl_endpoint
        @sqrl_endpoint ||= SQRL::Rails.endpoint_for(request)
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
    end
  end
end
