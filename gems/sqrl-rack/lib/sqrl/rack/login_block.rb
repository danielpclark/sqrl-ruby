# frozen_string_literal: true

require "cgi"

module SQRL
  module Rack
    # Framework-neutral HTML for a SQRL login: the link, the QR code and the status text
    # that +sqrl.js+ drives. Every framework integration renders this.
    module LoginBlock
      # Default status texts, overridable through +texts:+.
      DEFAULT_TEXTS = {
        message: "Scan the code with your SQRL client, or click the link if it is on this device.",
        cps: "Local SQRL client detected.",
        done: "Logged in, redirecting…",
        expired: "This login code expired. Reload the page to get a new one.",
        refresh: "Get a new code",
        unavailable: "SQRL login is temporarily unavailable. Please try again in a moment."
      }.freeze

      module_function

      # @param login_url [String, #to_s] the +sqrl://+ URL (a {Server::LoginURL} works)
      # @param status_url [String] cookie-bound poll endpoint
      # @param cancel_url [String, nil] renders a cancel link when given
      # @param qr [Boolean] include the QR code
      # @param qr_options [Hash] passed to {QR.svg}
      # @param link_text [String]
      # @param cancel_text [String]
      # @param texts [Hash] overrides for {DEFAULT_TEXTS} (+:message+, +:cps+, +:done+, +:expired+)
      # @param css_class [String] class of the root element (BEM children derive from it)
      # @param poll_ms [Integer] poll interval
      # @param script_url [String, nil] when given, a deferred +<script src>+ is appended
      # @param refresh_url [String, nil] JSON endpoint +sqrl.js+ calls to replace an
      #   expired login URL in place (renders a hidden "Get a new code" button)
      # @param extra_attrs [Hash] extra attributes on the root element
      # @return [String] HTML
      def render(login_url:, status_url:, cancel_url: nil, qr: true, qr_options: {}, link_text: "Sign in with SQRL",
                 cancel_text: "Cancel", texts: {}, css_class: "sqrl-login", poll_ms: 2000, script_url: nil,
                 refresh_url: nil, extra_attrs: {})
        url = login_url.to_s
        t = DEFAULT_TEXTS.merge(texts)
        attrs = {
          "class" => css_class, "data-sqrl-login" => "", "data-sqrl-url" => url, "data-sqrl-status" => status_url,
          "data-sqrl-poll" => poll_ms.to_i, "data-sqrl-text-message" => t[:message], "data-sqrl-text-cps" => t[:cps],
          "data-sqrl-text-done" => t[:done], "data-sqrl-text-expired" => t[:expired]
        }
        attrs["data-sqrl-refresh"] = refresh_url if refresh_url
        attrs.merge!(extra_attrs.transform_keys(&:to_s))
        html = "<div#{attributes(attrs)}>\n"
        html << %(  <a class="#{h(css_class)}__link" data-sqrl-link href="#{h(url)}" rel="nofollow">#{h(link_text)}</a>\n)
        html << %(  <div class="#{h(css_class)}__qr" data-sqrl-qr>#{QR.svg(url, **qr_options)}</div>\n) if qr
        html << %(  <p class="#{h(css_class)}__message" data-sqrl-message aria-live="polite">#{h(t[:message])}</p>\n)
        if refresh_url
          html << %(  <button type="button" class="#{h(css_class)}__refresh" data-sqrl-refresh-button hidden>#{h(t[:refresh])}</button>\n)
        end
        html << %(  <a class="#{h(css_class)}__cancel" href="#{h(cancel_url)}">#{h(cancel_text)}</a>\n) if cancel_url
        html << "</div>"
        html << "\n" << script_tag(src: script_url) if script_url
        html
      end

      # The markup shown instead of the login block when issuing a login URL was refused
      # (for example by a rate-limit hook).
      def unavailable(message: DEFAULT_TEXTS[:unavailable], css_class: "sqrl-login")
        %(<div class="#{h(css_class)} #{h(css_class)}--unavailable" data-sqrl-unavailable role="status">) \
          "#{h(message)}</div>"
      end

      # A script tag for +sqrl.js+: external when +src+ is given, inline otherwise.
      def script_tag(src: nil)
        if src
          %(<script src="#{h(src)}" defer></script>)
        else
          "<script>\n#{Assets.javascript}\n</script>"
        end
      end

      # Attribute names are escaped too; a name with characters outside the HTML attribute
      # name grammar is dropped rather than rendered.
      def attributes(hash)
        hash.map do |k, v|
          name = k.to_s
          next "" unless name.match?(/\A[A-Za-z_:][-A-Za-z0-9_:.]*\z/)

          v.to_s.empty? && name.start_with?("data-") ? " #{name}" : %( #{name}="#{h(v)}")
        end.join
      end
      private_class_method :attributes

      def h(str)
        CGI.escapeHTML(str.to_s)
      end
      private_class_method :h
    end
  end
end
