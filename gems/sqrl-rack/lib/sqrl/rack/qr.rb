# frozen_string_literal: true

require "rqrcode"
require "cgi"

module SQRL
  module Rack
    # QR code rendering for +sqrl://+ URLs.
    module QR
      module_function

      # Render +url+ as an accessible SVG QR code.
      #
      # @param url [String] the login URL
      # @param size [Integer] rendered width and height in CSS pixels (ignored when
      #   +module_size+ is given)
      # @param module_size [Integer, nil] pixels per QR module
      # @param color [String] foreground colour
      # @param background [String] background colour
      # @param title [String] accessible name
      # @param quiet_zone [Integer] modules of margin around the code
      # @param level [Symbol] error correction level (:l, :m, :q, :h)
      # @return [String] an +<svg role="img">+ element
      def svg(url, size: 256, module_size: nil, color: "#000000", background: "#ffffff",
              title: "SQRL login QR code", quiet_zone: 4, level: :m)
        modules = RQRCode::QRCode.new(url.to_s, level: level).modules
        count = modules.length
        total = count + (quiet_zone * 2)
        pixels = module_size ? module_size * total : size
        path = +""
        modules.each_with_index do |row, y|
          row.each_with_index do |dark, x|
            path << "M#{x + quiet_zone} #{y + quiet_zone}h1v1h-1z" if dark
          end
        end
        <<~SVG.strip
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 #{total} #{total}" width="#{pixels}" height="#{pixels}" role="img" aria-label="#{h(title)}" shape-rendering="crispEdges" class="sqrl-qr"><title>#{h(title)}</title><rect width="#{total}" height="#{total}" fill="#{h(background)}"/><path d="#{path}" fill="#{h(color)}"/></svg>
        SVG
      end

      # Render +url+ as PNG bytes (needs the +chunky_png+ gem that +rqrcode+ depends on).
      #
      # @return [String] binary PNG data
      def png(url, size: 256, level: :m)
        RQRCode::QRCode.new(url.to_s, level: level).as_png(size: size, border_modules: 4).to_s
      end

      def h(str)
        CGI.escapeHTML(str.to_s)
      end
      private_class_method :h
    end
  end
end
