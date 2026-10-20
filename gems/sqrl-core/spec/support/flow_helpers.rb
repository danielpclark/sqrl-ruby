# frozen_string_literal: true

# Helpers simulating the HTTPS transport between a SQRL::Session and a SQRL::Server::Handler.
module FlowHelpers
  IP = "203.0.113.7"

  def new_handler(**config)
    defaults = { host: "example.com", path: "/cli.sqrl" }
    SQRL::Server::Handler.new(config: SQRL::Server::Config.new(**defaults.merge(config)),
                              stores: SQRL::Server::Memory.stores)
  end

  def nut_of(request)
    SQRL::URL.query_pairs(request.url.split("?", 2)[1].to_s).to_h.fetch("nut")
  end

  # Pull the nut from the POST URL and hand the body to the handler.
  def post(handler, request, ip = IP)
    expect(request.url).to start_with("https://example.com/cli.sqrl?")
    handler.handle(nut: nut_of(request), body: request.body, ip: ip)
  end

  # Returns [pending_login_id, session].
  def new_session(handler, identity, options = SQRL::ClientOptions.new, **kw)
    login = handler.new_login_url(ip: IP, cancel_url: "/cancelled", **kw)
    [login.pending_login_id, SQRL::Session.new(identity, login.url, options: options)]
  end

  # POST the request, feed the reply, return the Result.
  def exchange(handler, session, request, ip = IP)
    result = post(handler, request, ip)
    session.feed(result.body)
    result
  end

  def identity(byte, previous = [])
    SQRL::UnlockedIdentity.from_iuk(byte.chr * 32, previous.map { |b| b.chr * 32 })
  end
end

RSpec.configure { |c| c.include FlowHelpers }
