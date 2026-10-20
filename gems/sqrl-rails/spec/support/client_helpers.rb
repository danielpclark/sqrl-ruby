# frozen_string_literal: true

require "cgi"

# Drives the two sides of a SQRL login against the dummy Rails application: a "browser"
# Rack::Test session (with cookies) views the login page, and a cookie-less "client"
# session POSTs the signed protocol requests from the same IP.
module ClientHelpers
  IP = "127.0.0.1"

  def app
    Rails.application
  end

  def identity(byte = 1)
    SQRL::UnlockedIdentity.from_iuk(byte.chr * 32)
  end

  def new_browser
    Rack::Test::Session.new(Rack::MockSession.new(app, "www.example.com"))
  end
  alias new_client new_browser

  def login_url_from(html)
    html[/data-sqrl-url="([^"]+)"/, 1]&.then { |u| CGI.unescapeHTML(u) }
  end

  def post_sqrl(client, session, request, ip: IP)
    uri = URI.parse(request.url)
    client.post("#{uri.path}?#{uri.query}", request.body,
                { "CONTENT_TYPE" => "application/x-www-form-urlencoded", "REMOTE_ADDR" => ip })
    expect(client.last_response.status).to eq(200)
    session.feed(client.last_response.body)
  end

  # Full query + ident against the URL found on the login page.
  def sqrl_login(client, url, id = identity, cps: true, ip: IP)
    session = SQRL::Session.new(id, url, options: SQRL::ClientOptions.new(cps: cps))
    post_sqrl(client, session, session.query, ip: ip)
    post_sqrl(client, session, session.ident, ip: ip)
    session
  end

  # View the login page with the browser and return [url, browser].
  def open_login_page(browser = new_browser, path: "/session/new")
    browser.get(path, {}, { "REMOTE_ADDR" => IP })
    expect(browser.last_response.status).to eq(200)
    url = login_url_from(browser.last_response.body)
    expect(url).to start_with("qrl://").or start_with("sqrl://")
    [url, browser]
  end

  # Follow a redirect with the browser, from the same IP.
  def follow(browser)
    expect(browser.last_response).to be_redirect
    browser.get(browser.last_response.location, {}, { "REMOTE_ADDR" => IP })
  end
end

RSpec.configure { |c| c.include ClientHelpers }
