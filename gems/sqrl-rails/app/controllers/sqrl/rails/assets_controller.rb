# frozen_string_literal: true

module SQRL
  module Rails
    # Serves +sqrl.js+ with an ETag.
    class AssetsController < ApplicationController
      # A public static script; Rails' cross-origin JavaScript check does not apply.
      skip_forgery_protection

      def script
        status, headers, body = sqrl_endpoint.script(request)
        headers.each { |k, v| response.set_header(k, v) }
        if status == 304
          head :not_modified
        else
          render body: body.join, status: status, content_type: "application/javascript"
        end
      end
    end
  end
end
