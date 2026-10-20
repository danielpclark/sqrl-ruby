# frozen_string_literal: true

require "uri"

module SQRL
  module Client
    # Finds the SQRL login URL on a login page.
    #
    # Search order:
    # 1. +data-sqrl-url+ on the +[data-sqrl-login]+ element rendered by the sqrl-rack /
    #    sqrl-rails helpers (plus +data-sqrl-status+ for the poll endpoint);
    # 2. +a[data-sqrl-link]+;
    # 3. any +href+ that is a +sqrl://+ URL (or +qrl://+ on a loopback host);
    # 4. +href="http://localhost:25519/<base64url>"+ CPS-style links, decoded back to the
    #    +sqrl://+ URL they carry;
    # 5. a bare +sqrl://+ URL anywhere in the page text.
    #
    # A tolerant scanner is used by default; Nokogiri is used for attribute extraction
    # when it is available.
    module Discovery
      # What was found on a page.
      Result = Struct.new(:sqrl_url, :status_url, :source, :page_url, keyword_init: true) do
        def inspect
          "#<SQRL::Client::Discovery::Result #{sqrl_url} (#{source})>"
        end
      end

      CPS_LINK = %r{\Ahttps?://(?:localhost|127\.0\.0\.1):25519/([A-Za-z0-9_-]+)\z}i
      SQRL_URL = %r{\b(s?qrl://[^\s"'<>\\]+)}i
      ATTR = ->(name) { /#{name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i }

      module_function

      # @param html [String] the page
      # @param base_url [String, nil] the page's URL, for resolving relative status URLs
      # @return [Result]
      # @raise [DiscoveryError]
      def find(html, base_url: nil)
        html = html.to_s
        direct = from_target(html.strip)
        return direct if direct && html.strip.length < 2048 && !html.include?("<")

        status = status_url(html, base_url)
        candidates = []
        candidates << [attribute_value(html, "data-sqrl-url"), "data-sqrl-url"]
        candidates << [attribute_on(html, /<a\b[^>]*data-sqrl-link[^>]*>/i, "href"), "a[data-sqrl-link]"]
        hrefs(html).each { |h| candidates << [h, "href"] }
        html.scan(SQRL_URL) { |m| candidates << [m[0], "text"] }

        candidates.each do |(value, source)|
          next if value.nil? || value.empty?

          url = normalize(unescape(value))
          next unless url

          return Result.new(sqrl_url: url, status_url: status, source: source, page_url: base_url)
        end
        raise DiscoveryError, "no sqrl:// login link found#{" on #{base_url}" if base_url}"
      end

      # Turn a target string that is itself a login link into a Result: a +sqrl://+ /
      # +qrl://+ URL or a +localhost:25519/<b64u>+ CPS link. Returns nil for anything else
      # (a page URL to fetch, or HTML).
      def from_target(target)
        url = normalize(target.to_s.strip)
        url && Result.new(sqrl_url: url, source: "target")
      end

      # Validate / decode one candidate into a +sqrl://+ URL string, or nil.
      def normalize(value)
        value = value.to_s.strip
        return nil if value.empty?

        if (m = value.match(CPS_LINK))
          decoded = Util.b64u_decode(m[1]).force_encoding(Encoding::UTF_8)
          return nil unless decoded.valid_encoding?

          value = decoded.strip
        end
        return nil unless value.match?(%r{\As?qrl://}i)

        URL.parse(value).original
      rescue SQRL::Error
        nil
      end

      def status_url(html, base_url)
        raw = attribute_value(html, "data-sqrl-status")
        return nil if raw.nil? || raw.empty?

        raw = unescape(raw)
        base_url ? URI.join(base_url, raw).to_s : raw
      rescue URI::Error
        nil
      end

      def hrefs(html)
        html.scan(/<a\b[^>]*>/i).filter_map { |tag| attribute_in_tag(tag, "href") }
      end

      def attribute_value(html, name)
        tag = html[/<[^>]*\b#{Regexp.escape(name)}\s*=[^>]*>/i]
        tag && attribute_in_tag(tag, name)
      end

      def attribute_on(html, tag_regex, name)
        tag = html[tag_regex]
        tag && attribute_in_tag(tag, name)
      end

      def attribute_in_tag(tag, name)
        m = tag.match(ATTR.call(Regexp.escape(name)))
        m && (m[1] || m[2] || m[3])
      end

      def unescape(str)
        str.gsub("&amp;", "&").gsub("&quot;", '"').gsub("&#39;", "'").gsub("&lt;", "<").gsub("&gt;", ">")
      end
    end
  end
end
