# frozen_string_literal: true

require "net/http"
require "uri"
require "http-cookie"

module SQRL
  module Client
    # The HTTP layer: Net::HTTP with a persistent cookie jar, redirects, timeouts and the
    # plain-http policy SQRL needs (+https+ everywhere, +http+ only for loopback hosts
    # while developing).
    #
    # Anything responding to +get(url, headers)+ and +post_form(url, body, headers)+ and
    # returning a {Response} can replace it (for example a Faraday adapter).
    class Transport
      # An HTTP response after redirects were followed.
      Response = Struct.new(:status, :headers, :body, :final_url, :redirects, keyword_init: true) do
        def success? = (200..299).cover?(status)
        def redirect? = (300..399).cover?(status)

        def [](name) = headers[name.to_s.downcase]

        def json
          require "json"
          JSON.parse(body)
        rescue JSON::ParserError
          nil
        end

        def inspect
          "#<SQRL::Client::Transport::Response #{status} #{final_url}>"
        end
      end

      REDIRECT_STATUSES = [301, 302, 303, 307, 308].freeze
      DEFAULT_USER_AGENT = "sqrl-client/#{SQRL::VERSION} (Ruby #{RUBY_VERSION})".freeze

      # @return [HTTP::CookieJar]
      attr_reader :cookies
      attr_accessor :open_timeout, :read_timeout, :max_redirects, :user_agent, :logger

      # @param cookies [HTTP::CookieJar] shared cookie jar
      # @param allow_http [Symbol, Boolean] +false+ (default) never speaks plain http;
      #   +:loopback+ permits it for loopback hosts only (testing); +true+ everywhere
      # @param verify_tls [Boolean]
      # @param ca_file [String, nil]
      # @param proxy [String, nil, :env] proxy URL; +:env+ (default) honours +http_proxy+ /
      #   +https_proxy+ / +no_proxy+; loopback hosts never go through a proxy
      def initialize(cookies: HTTP::CookieJar.new, allow_http: false, verify_tls: true, ca_file: nil,
                     proxy: :env, open_timeout: 10, read_timeout: 30, max_redirects: 10,
                     user_agent: DEFAULT_USER_AGENT, logger: nil)
        @cookies = cookies
        @allow_http = allow_http
        @verify_tls = verify_tls
        @ca_file = ca_file
        @proxy = proxy
        @open_timeout = open_timeout
        @read_timeout = read_timeout
        @max_redirects = max_redirects
        @user_agent = user_agent
        @logger = logger
      end

      # GET +url+, following redirects with the cookie jar.
      def get(url, headers = {}, follow_redirects: true)
        request(:get, url, nil, headers, follow_redirects: follow_redirects)
      end

      # POST an +application/x-www-form-urlencoded+ body (already encoded).
      def post_form(url, body, headers = {}, follow_redirects: true)
        headers = { "Content-Type" => "application/x-www-form-urlencoded" }.merge(headers)
        request(:post, url, body, headers, follow_redirects: follow_redirects)
      end

      # Remove every cookie (a fresh "browser").
      def clear_cookies!
        @cookies.clear
        self
      end

      # Cookies in Netscape +cookies.txt+ format (what curl reads with +-b+).
      def cookies_netscape
        lines = ["# Netscape HTTP Cookie File"]
        @cookies.each do |c|
          domain = c.for_domain? ? ".#{c.domain}" : c.domain
          expires = c.expires ? c.expires.to_i : 0
          lines << [domain, c.for_domain? ? "TRUE" : "FALSE", c.path, c.secure? ? "TRUE" : "FALSE",
                    expires, c.name, c.value].join("\t")
        end
        "#{lines.join("\n")}\n"
      end

      # Cookies as an Array of Hashes (serialisable to JSON).
      def cookies_as_hashes
        @cookies.map do |c|
          { name: c.name, value: c.value, domain: c.domain, path: c.path, secure: c.secure?,
            httponly: c.httponly?, expires: c.expires&.iso8601 }
        end
      end

      private

      def request(method, url, body, headers, follow_redirects:, redirects: 0)
        uri = URI.parse(url.to_s)
        check_scheme!(uri)
        http = build_http(uri)
        req = build_request(method, uri, body, headers)
        @logger&.debug { "[sqrl-client] #{method.to_s.upcase} #{uri}" }
        res = http.start { |h| h.request(req) }
        store_cookies(res, uri)
        status = res.code.to_i
        if follow_redirects && REDIRECT_STATUSES.include?(status) && res["location"]
          raise TransportError.new("too many redirects", url: url) if redirects >= @max_redirects

          target = uri.merge(res["location"]).to_s
          next_method = [307, 308].include?(status) ? method : :get
          next_body = next_method == :get ? nil : body
          next_headers = next_method == :get ? headers.reject { |k, _| k.to_s.casecmp?("content-type") } : headers
          return request(next_method, target, next_body, next_headers, follow_redirects: true,
                                                                       redirects: redirects + 1)
        end
        Response.new(status: status, headers: res.each_header.to_h, body: res.body.to_s,
                     final_url: uri.to_s, redirects: redirects)
      rescue SystemCallError, Timeout::Error, OpenSSL::SSL::SSLError, SocketError, EOFError, Net::ProtocolError => e
        raise TransportError.new("#{method.to_s.upcase} #{url}: #{e.class}: #{e.message}", url: url)
      end

      def check_scheme!(uri)
        case uri.scheme
        when "https" then nil
        when "http"
          allowed = @allow_http == true || (@allow_http == :loopback && URL.loopback?(uri.host.to_s.downcase))
          unless allowed
            raise TransportError.new("plain http is not allowed for #{uri.host} (allow_http: #{@allow_http.inspect})",
                                     url: uri.to_s)
          end
        else
          raise TransportError.new("unsupported URL scheme #{uri.scheme.inspect}", url: uri.to_s)
        end
      end

      def build_http(uri)
        http =
          if URL.loopback?(uri.host.to_s.downcase) || @proxy.nil?
            Net::HTTP.new(uri.host, uri.port, nil)
          elsif @proxy == :env
            Net::HTTP.new(uri.host, uri.port)
          else
            p = URI.parse(@proxy.to_s)
            Net::HTTP.new(uri.host, uri.port, p.host, p.port, p.user, p.password)
          end
        http.open_timeout = @open_timeout
        http.read_timeout = @read_timeout
        if uri.scheme == "https"
          http.use_ssl = true
          http.verify_mode = @verify_tls ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
          http.ca_file = @ca_file if @ca_file
        end
        http
      end

      def build_request(method, uri, body, headers)
        klass = method == :post ? Net::HTTP::Post : Net::HTTP::Get
        req = klass.new(uri.request_uri)
        req["User-Agent"] = @user_agent
        req["Accept"] ||= "*/*"
        headers.each { |k, v| req[k.to_s] = v }
        cookie = HTTP::Cookie.cookie_value(@cookies.cookies(uri))
        req["Cookie"] = cookie unless cookie.empty?
        req.body = body if body
        req
      end

      def store_cookies(res, uri)
        res.get_fields("set-cookie")&.each do |value|
          HTTP::Cookie.parse(value, uri).each { |c| @cookies.add(c) }
        rescue StandardError => e
          @logger&.warn { "[sqrl-client] ignoring unparsable cookie: #{e.message}" }
        end
      end
    end
  end
end
