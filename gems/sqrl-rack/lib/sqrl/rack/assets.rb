# frozen_string_literal: true

require "digest"

module SQRL
  module Rack
    # The browser-side script shipped with the gem (+assets/sqrl.js+).
    module Assets
      ASSETS_DIR = File.expand_path("../../../assets", __dir__)

      module_function

      # Absolute path of +sqrl.js+.
      def javascript_path
        File.join(ASSETS_DIR, "sqrl.js")
      end

      # Contents of +sqrl.js+ (memoized).
      def javascript
        @javascript ||= File.read(javascript_path, encoding: "UTF-8").freeze
      end

      # Short content digest, usable as an ETag or cache-busting token.
      def javascript_digest
        @javascript_digest ||= Digest::SHA256.hexdigest(javascript)[0, 16].freeze
      end
    end
  end
end
