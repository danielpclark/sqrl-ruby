# frozen_string_literal: true

# Drives the SQRL client side of a login against a Rack app under test: a "browser"
# (one Rack::Test session, with cookies) views the login page, and a separate
# cookie-less "client" session POSTs the signed protocol requests.
module ClientHelpers
  BROWSER_IP = "198.51.100.10"

  def identity(byte = 1)
    SQRL::UnlockedIdentity.from_iuk(byte.chr * 32)
  end

  def new_browser(app = self.app)
    Rack::Test::Session.new(Rack::MockSession.new(app, "example.com"))
  end

  def new_client(app = self.app)
    Rack::Test::Session.new(Rack::MockSession.new(app, "example.com"))
  end

  # Extract the sqrl:// (or qrl://) URL from a rendered login block.
  def login_url_from(html)
    html[/data-sqrl-url="([^"]+)"/, 1]&.then { |u| CGI.unescapeHTML(u) }
  end

  # POST one signed request with the cookie-less client session and feed the reply.
  def post_sqrl(client, session, request, ip: BROWSER_IP)
    uri = URI.parse(request.url)
    client.post("#{uri.path}?#{uri.query}", request.body,
                { "CONTENT_TYPE" => "application/x-www-form-urlencoded", "REMOTE_ADDR" => ip })
    expect(client.last_response.status).to eq(200)
    session.feed(client.last_response.body)
  end

  # Full query + ident against the URL found on the login page.
  def sqrl_login(client, url, id = identity, cps: true, ip: BROWSER_IP)
    session = SQRL::Session.new(id, url, options: SQRL::ClientOptions.new(cps: cps))
    post_sqrl(client, session, session.query, ip: ip)
    post_sqrl(client, session, session.ident, ip: ip)
    session
  end
end

RSpec.configure { |c| c.include ClientHelpers }
