# frozen_string_literal: true

require_relative "support/flow_helpers"

# End-to-end protocol flows between SQRL::Session (client) and SQRL::Server::Handler.
RSpec.describe "protocol flows" do
  def b64(str) = SQRL::Util.b64u_encode(str)

  it "creates an account then logs in with CPS" do
    handler = new_handler
    id = identity(1)
    opts = SQRL::ClientOptions.new(cps: true)

    # First visit: unknown identity -> create the account.
    sid, s = new_session(handler, id, opts)
    q = s.query
    expect(q.command).to eq(:query)
    r = exchange(handler, s, q)
    expect(r.tif).not_to be_id_match
    expect(r.tif).to be_ips_matched
    expect(r.command).to eq(:query)
    expect(r.pending_login_id).to eq(sid)
    expect(s.state).to eq(:unknown)
    ident = s.ident
    expect(ident.client_text).to include("suk=", "vuk=", "opt=cps")
    r = exchange(handler, s, ident)
    expect(r.tif).to be_id_match
    expect(r).to be_authenticated
    expect(r).to be_created
    expect(r.identity.idk).to eq(s.idk)
    expect(s.state).to eq(SQRL::Session::State.new(kind: :known, disabled: false))
    expect(handler.stores.pending_logins.find(sid).authenticated_idk).to eq(s.idk)
    # CPS: the browser that started the login is not signed in by the server; only the
    # browser the client redirects to the url= token is.
    expect(handler.stores.pending_logins.find(sid)).to be_cps
    expect(handler.status(sid)).to eq(authenticated: false, idk: nil)
    cps = s.cps_url
    expect(cps).to eq(r.cps_url)
    expect(cps).to start_with("https://example.com/sqrl/callback?t=")
    expect(s.cancel_url).to eq("https://example.com/cancelled")
    expect(handler.stores.identities.count).to eq(1)
    # the CPS token completes the login exactly once
    token = cps[/t=(.+)\z/, 1]
    claimed = handler.claim_cps(token)
    expect(claimed.id).to eq(sid)
    expect(claimed.authenticated_idk).to eq(s.idk)
    expect(handler.claim_cps(token)).to be_nil

    # Second visit: known identity -> plain login, no suk/vuk needed.
    sid2, s2 = new_session(handler, id, opts)
    r = exchange(handler, s2, s2.query)
    expect(r.tif).to be_id_match
    # suk was requested by the query, so the server returned it
    expect(s2.last_response.suk).not_to be_nil
    ident = s2.ident
    expect(ident.client_text).not_to include("suk=")
    r = exchange(handler, s2, ident)
    expect(r.tif).to be_id_match
    expect(r.tif).not_to be_error
    expect(r).not_to be_created
    expect(handler.stores.pending_logins.find(sid2).authenticated_idk).to eq(s2.idk)
    expect(handler.stores.identities.find(s2.idk).logins).to eq(2)
  end

  it "disables, enables and removes with the rescue code" do
    handler = new_handler
    iuk = 2.chr * 32
    id = identity(2)

    # create
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    exchange(handler, s, s.ident)

    # disable
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    r = exchange(handler, s, s.disable)
    expect(r.tif).to be_sqrl_disabled
    expect(r.tif).not_to be_error
    expect(handler.stores.identities.find(s.idk)).to be_disabled

    # login now fails
    sid, s = new_session(handler, id)
    exchange(handler, s, s.query)
    expect(s.state).to eq(SQRL::Session::State.new(kind: :known, disabled: true))
    r = exchange(handler, s, s.ident)
    expect(r.tif).to be_command_failed
    expect(r).not_to be_authenticated
    expect(handler.stores.pending_logins.find(sid).authenticated_idk).to be_nil
    expect(handler.status(sid)).to eq(authenticated: false, idk: nil)

    # enable needs the IUK
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    expect { s.enable(nil) }.to raise_error(SQRL::ProtocolError)
    # wrong IUK -> signature does not verify
    r = exchange(handler, s, s.enable(3.chr * 32))
    expect(r.tif).to be_command_failed
    expect(handler.stores.identities.find(s.idk)).to be_disabled

    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    e = s.enable(iuk)
    expect(e.body).to include("&urs=")
    r = exchange(handler, s, e)
    expect(r.tif).not_to be_sqrl_disabled
    expect(r.tif).not_to be_error
    expect(r).to be_authenticated
    expect(handler.stores.identities.find(s.idk)).not_to be_disabled

    # remove
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    r = exchange(handler, s, s.remove(iuk))
    expect(r.tif).not_to be_id_match
    expect(r.tif).not_to be_error
    expect(r.identity).to be_nil
    expect(handler.stores.identities.count).to eq(0)
  end

  it "re-keys the account to the new identity" do
    handler = new_handler
    old = identity(4)
    _, s = new_session(handler, old)
    exchange(handler, s, s.query)
    exchange(handler, s, s.ident)
    old_idk = s.idk

    # Re-keyed identity carries the old IUK as a previous identity.
    new = identity(5, [4])
    sid, s = new_session(handler, new)
    q = s.query
    expect(q.client_text).to include("pidk=")
    expect(q.body).to include("&pids=")
    r = exchange(handler, s, q)
    expect(r.tif).to be_previous_id_match
    expect(r.tif).not_to be_id_match
    expect(s.state).to eq(SQRL::Session::State.new(kind: :previous_known, disabled: false))
    expect(s.last_response.suk).not_to be_nil
    i = s.ident
    expect(i.client_text).to include("pidk=", "suk=", "vuk=")
    expect(i.body).to include("&pids=", "&urs=")
    r = exchange(handler, s, i)
    expect(r.tif).to be_id_match
    expect(r.tif).not_to be_previous_id_match # the TIF describes the account after the update
    expect(r.tif).not_to be_error
    expect(r.rekeyed_from).to eq(old_idk)
    expect(r).to be_rekeyed
    expect(handler.stores.pending_logins.find(sid).authenticated_idk).to eq(s.idk)
    expect(handler.stores.identities.find(s.idk)).not_to be_nil
    expect(handler.stores.identities.find(old_idk)).to be_nil
    expect(handler.stores.identities).to be_superseded(old_idk)

    # The old identity is now superseded.
    _, s = new_session(handler, old)
    r = exchange(handler, s, s.query)
    expect(r.tif).to be_identity_superseded
    expect(r.tif.to_hex).to eq("240") # exactly, per "Handling Superseded Identities"
    expect(s.state).to eq(:superseded)

    # The new identity logs in normally from now on, without re-keying.
    _, s = new_session(handler, new)
    r = exchange(handler, s, s.query)
    expect(r.tif).to be_id_match
    i = s.ident
    expect(i.client_text).not_to include("suk=")
    r = exchange(handler, s, i)
    expect(r.tif).not_to be_error
    expect(r).not_to be_rekeyed
  end

  it "tries older previous identities in turn" do
    handler = new_handler
    oldest = identity(6)
    _, s = new_session(handler, oldest)
    exchange(handler, s, s.query)
    exchange(handler, s, s.ident)

    # identity re-keyed twice since: previous = [middle, oldest]
    current = identity(8, [7, 6])
    _, s = new_session(handler, current)
    r = exchange(handler, s, s.query)
    expect(s.state).to eq(:unknown)
    expect(r.tif).not_to be_previous_id_match
    expect(s.try_next_previous).to be(true)
    r = exchange(handler, s, s.query)
    expect(r.tif).to be_previous_id_match
    expect(s.try_next_previous).to be(false)
    r = exchange(handler, s, s.ident)
    expect(r.tif).to be_id_match
    expect(r.tif).not_to be_error
    expect(handler.stores.identities.find(s.idk)).not_to be_nil
  end

  it "enables and removes via a previous identity without the rescue code" do
    handler = new_handler
    old = identity(9)
    _, s = new_session(handler, old)
    exchange(handler, s, s.query)
    exchange(handler, s, s.ident)
    _, s = new_session(handler, old)
    exchange(handler, s, s.query)
    exchange(handler, s, s.disable)

    new = identity(10, [9])
    _, s = new_session(handler, new)
    r = exchange(handler, s, s.query)
    expect(s.state).to eq(SQRL::Session::State.new(kind: :previous_known, disabled: true))
    expect(r.tif).to be_sqrl_disabled
    r = exchange(handler, s, s.enable(nil))
    expect(r.tif).to be_id_match
    expect(r.tif).not_to be_sqrl_disabled
    expect(r.tif).not_to be_error
    expect(handler.stores.identities.find(s.idk)).not_to be_disabled

    _, s = new_session(handler, new)
    exchange(handler, s, s.query)
    # now a current match: remove needs the new IUK
    expect { s.remove(nil) }.to raise_error(SQRL::ProtocolError)
    r = exchange(handler, s, s.remove(10.chr * 32))
    expect(r.tif).not_to be_error
    expect(handler.stores.identities.count).to eq(0)
  end

  it "poses an ask and records the btn" do
    ask = SQRL::Ask.new(message: "Create an account on example.com?", buttons: [{ label: "Yes" }, { label: "No" }])
    handler = new_handler(ask: ask)
    id = identity(11)
    # An ask is only valid once the server recognises the current identity, so create the
    # account first; no question is posed to an unknown identity.
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    expect(s.pending_ask).to be_nil
    r = exchange(handler, s, s.ident)
    expect(r.tif).to be_id_match

    sid, s = new_session(handler, id)
    exchange(handler, s, s.query)
    pending = s.pending_ask
    expect(pending.message).to eq("Create an account on example.com?")
    expect(pending.buttons.length).to eq(2)
    # Without an answer the server refuses to proceed.
    i = s.ident
    expect(i.client_text).not_to include("btn=")
    r = exchange(handler, s, i)
    expect(r.tif).to be_command_failed
    # Answer and re-query.
    s.set_button(2)
    expect(s.pending_ask).to be_nil
    q = s.query
    expect(q.client_text).to include("btn=2\r\n")
    exchange(handler, s, q)
    expect(s.pending_ask).to be_nil
    expect(handler.stores.pending_logins.find(sid).btn).to eq(2)
    r = exchange(handler, s, s.ident)
    expect(r.tif).to be_id_match
    expect(r.tif).not_to be_error
  end

  it "refuses an ident answered with a button the ask does not accept" do
    ask = SQRL::Ask.new(message: "Allow this login?", buttons: [{ label: "Allow" }, { label: "Deny" }], accept: [1])
    expect(ask.accepts?(1)).to be(true)
    expect(ask.accepts?(2)).to be(false)
    expect(SQRL::Ask.new(message: "x").accepts?(2)).to be(true)
    expect(SQRL::Ask.parse(ask.to_wire).accept).to be_nil
    handler = new_handler(ask: ask)
    id = identity(12)
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    exchange(handler, s, s.ident) # creates the account; the ask is posed from now on

    sid, s = new_session(handler, id)
    exchange(handler, s, s.query)
    expect(s.pending_ask).not_to be_nil
    s.set_button(2) # Deny
    exchange(handler, s, s.query)
    expect(handler.stores.pending_logins.find(sid).btn).to eq(2)
    r = exchange(handler, s, s.ident)
    expect(r.tif).to be_command_failed
    expect(r).not_to be_authenticated
    expect(handler.stores.pending_logins.find(sid)).not_to be_authenticated

    s.set_button(1) # Allow, in the same transaction
    exchange(handler, s, s.query)
    r = exchange(handler, s, s.ident)
    expect(r.tif).not_to be_error
    expect(r).to be_authenticated
  end

  it "supports a dynamic ask" do
    asked = []
    handler = new_handler(ask: lambda { |ctx|
      asked << ctx[:idk]
      ctx[:identity] ? SQRL::Ask.new(message: "Welcome back?") : nil
    })
    id = identity(21)
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    exchange(handler, s, s.ident)
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    expect(s.pending_ask.message).to eq("Welcome back?")
    expect(asked).to include(s.idk)
  end

  it "stores and re-checks the indexed secret (sin/ins)" do
    handler = new_handler(sin: "0")
    id = identity(12)
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    i = s.ident
    expect(i.client_text).to include("ins=")
    exchange(handler, s, i)
    ins1 = handler.stores.identities.find(s.idk).ins
    expect(ins1).not_to be_nil

    # The same identity produces the same indexed secret next time.
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    r = exchange(handler, s, s.ident)
    expect(r.tif).not_to be_error
    expect(handler.stores.identities.find(s.idk).ins).to eq(ins1)

    # pins accompanies pidk when a previous identity is offered.
    new = identity(13, [12])
    _, s = new_session(handler, new)
    exchange(handler, s, s.query)
    i = s.ident
    expect(i.client_text).to include("ins=", "pins=")
    r = exchange(handler, s, i)
    expect(r.tif).not_to be_error
    expect(handler.stores.identities.find(s.idk).ins).not_to eq(ins1)
  end

  it "refuses an ident whose ins does not match the stored one" do
    handler = new_handler(sin: "0")
    id = identity(22)
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    exchange(handler, s, s.ident)
    handler.stores.identities.update(s.idk, ins: "something-else")
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    r = exchange(handler, s, s.ident)
    expect(r.tif).to be_command_failed
    expect(r).not_to be_authenticated
  end

  it "answers a stale nut with the same transient error twice (the client's cue to refresh)" do
    handler = new_handler
    id = identity(14)
    _, s = new_session(handler, id)
    q = s.query
    s.feed(post(handler, q).body)
    r2 = handler.handle(nut: "nope", body: q.body, ip: FlowHelpers::IP)
    expect(r2.tif).to be_transient_error
    s.feed(r2.body)
    expect(s.state).to eq(:transient)
    # This server keeps its state by reference, so the browser session behind the stale nut is
    # gone: the retry with the fresh nut must fail with exactly the same TIF, never log the
    # client in to a pending login no browser owns.
    r = exchange(handler, s, s.query)
    expect(r.tif).to eq(r2.tif)
    expect(s.state).to eq(:transient)
  end

  it "treats a reused nut as a transient error" do
    handler = new_handler
    id = identity(23)
    _, s = new_session(handler, id)
    q = s.query
    first = post(handler, q)
    expect(first.tif).not_to be_error
    replay = handler.handle(nut: nut_of(q), body: q.body, ip: FlowHelpers::IP)
    expect(replay.tif).to be_transient_error
    expect(replay.tif).to be_command_failed
  end

  it "detects tampering" do
    handler = new_handler
    id = identity(15)
    _, s = new_session(handler, id)
    q = s.query
    nut = nut_of(q)

    # Modified server parameter -> client failure.
    bad_server = b64("sqrl://example.com/cli.sqrl?nut=other")
    tampered = q.body.sub(q.body[/&server=([^&]+)/, 1], bad_server)
    r = handler.handle(nut: nut, body: tampered, ip: FlowHelpers::IP)
    s.feed(r.body)
    expect(s.state).to be_failed
    expect(r.tif).to be_client_failure

    # Corrupted signature -> client failure.
    _, s = new_session(handler, id)
    q = s.query
    body = q.body.dup
    body[-1] = body.end_with?("A") ? "B" : "A"
    r = handler.handle(nut: nut_of(q), body: body, ip: FlowHelpers::IP)
    expect(s.feed(r.body).tif).to be_client_failure

    # Modified client text (re-encoded) -> signature no longer verifies.
    _, s = new_session(handler, id)
    q = s.query
    client = SQRL::Util.b64u_decode(q.body[/client=([^&]+)/, 1]).sub("cmd=query", "cmd=ident")
    body = q.body.sub(q.body[/client=([^&]+)/, 1], b64(client))
    r = handler.handle(nut: nut_of(q), body: body, ip: FlowHelpers::IP)
    expect(r.tif).to be_client_failure

    # Garbage bodies are client failures, not exceptions.
    _, s = new_session(handler, id)
    q = s.query
    expect(handler.handle(nut: nut_of(q), body: "client=%%%&server=x&ids=y",
                          ip: FlowHelpers::IP).tif).to be_client_failure
    _, s = new_session(handler, id)
    q = s.query
    expect(handler.handle(nut: nut_of(q), body: "", ip: FlowHelpers::IP).tif).to be_client_failure

    # Response steering the client to another host is rejected by the client.
    _, s = new_session(handler, id)
    evil = b64("ver=1\r\nnut=x\r\ntif=0\r\nqry=https://evil.example/cli.sqrl?nut=x\r\n")
    expect { s.feed(evil) }.to raise_error(SQRL::ProtocolError)
    evil = b64("ver=1\r\nnut=x\r\ntif=0\r\nqry=//evil.example/cli.sqrl?nut=x\r\n")
    expect { s.feed(evil) }.to raise_error(SQRL::ProtocolError)

    # CPS url on another host is rejected.
    evil = b64("ver=1\r\nnut=x\r\ntif=1\r\nqry=/cli.sqrl?nut=x\r\nurl=https://evil.example/\r\n")
    s.feed(evil)
    expect { s.cps_url }.to raise_error(SQRL::ProtocolError)
  end

  it "rejects unknown commands and versions" do
    handler = new_handler
    id = identity(24)
    _, s = new_session(handler, id)
    q = s.query
    client = SQRL::Util.b64u_decode(q.body[/client=([^&]+)/, 1])
    rebuild = lambda do |text|
      client_b64 = b64(text)
      server_b64 = q.body[/&server=([^&]+)/, 1]
      ids = SQRL::Crypto.ed25519_sign(id.site_seed("example.com"), client_b64 + server_b64)
      "client=#{client_b64}&server=#{server_b64}&ids=#{b64(ids)}"
    end
    r = handler.handle(nut: nut_of(q), body: rebuild.call(client.sub("cmd=query", "cmd=frobnicate")), ip: FlowHelpers::IP)
    expect(r.tif).to be_function_not_supported
    _, s = new_session(handler, id)
    q = s.query
    r = handler.handle(nut: nut_of(q), body: rebuild.call(client.sub("ver=1", "ver=7")), ip: FlowHelpers::IP)
    expect(r.tif).to be_client_failure
  end

  it "refuses an IP mismatch unless noiptest" do
    handler = new_handler
    id = identity(16)
    _, s = new_session(handler, id)
    r = post(handler, s.query, "198.51.100.1")
    s.feed(r.body)
    expect(r.tif).not_to be_ips_matched
    expect(r.tif).to be_command_failed
    expect(r.tif.value).to eq(SQRL::Tif::COMMAND_FAILED)
    expect(s).to be_ip_check_failed

    _, s = new_session(handler, id, SQRL::ClientOptions.new(noiptest: true))
    r = post(handler, s.query, "198.51.100.1")
    s.feed(r.body)
    expect(r.tif).not_to be_ips_matched
    expect(r.tif).not_to be_error

    relaxed = new_handler(require_ip_match: false)
    _, s = new_session(relaxed, id)
    r = post(relaxed, s.query, "198.51.100.1")
    expect(r.tif).not_to be_ips_matched
    expect(r.tif).not_to be_error
  end

  it "records on the pending login whether the authenticating request's IP matched" do
    handler = new_handler
    id = identity(17)
    login_id, s = new_session(handler, id)
    exchange(handler, s, s.query)
    exchange(handler, s, s.ident)
    expect(handler.stores.pending_logins.find(login_id).ip_matched).to be(true)

    login_id, s = new_session(handler, id, SQRL::ClientOptions.new(noiptest: true))
    s.feed(post(handler, s.query, "198.51.100.1").body)
    s.feed(post(handler, s.ident, "198.51.100.1").body)
    expect(s.state).to eq(:known)
    pending = handler.stores.pending_logins.find(login_id)
    expect(pending).to be_authenticated
    expect(pending.ip_matched).to be(false)
  end

  it "flags a different identity mid-session as a bad association" do
    handler = new_handler
    a = identity(17)
    b = identity(18)
    _, sa = new_session(handler, a)
    resp = sa.feed(post(handler, sa.query).body)
    # identity B continues A's transaction
    sb = SQRL::Session.new(b, sa.url)
    sb.feed(resp.raw)
    r = post(handler, sb.ident)
    expect(r.tif).to be_bad_id_association
    expect(sb.feed(r.body).tif).to be_bad_id_association
    expect(sb.state).to be_failed
  end

  it "yields a different identity for an Alt-ID on the same site" do
    id = identity(19)
    url = SQRL::URL.parse("sqrl://example.com/cli.sqrl?nut=1")
    plain = SQRL::Session.new(id, url)
    alt = SQRL::Session.new(id, url, alt_id: "work")
    expect(plain.idk).not_to eq(alt.idk)

    handler = new_handler
    _, s = new_session(handler, id)
    exchange(handler, s, s.query)
    exchange(handler, s, s.ident)
    login = handler.new_login_url(ip: FlowHelpers::IP)
    s_alt = SQRL::Session.new(id, login.url, alt_id: "work")
    r = exchange(handler, s_alt, s_alt.query)
    expect(r.tif).not_to be_id_match
  end

  it "scopes identities with the path extension" do
    handler = new_handler(path: "/app/cli.sqrl", path_extension: 4)
    login = handler.new_login_url(ip: FlowHelpers::IP)
    expect(login.url).to start_with("sqrl://example.com/app/cli.sqrl?x=4&nut=")
    url = SQRL::URL.parse(login.url)
    expect(url.site_key).to eq("example.com/app")
    s = SQRL::Session.new(identity(20), url)
    r = handler.handle(nut: nut_of(s.query), body: s.query.body, ip: FlowHelpers::IP)
    # the second query call rebuilt the request; the first nut was never sent, so this is
    # a plain unknown-identity answer
    expect(r.tif).not_to be_error
  end
end
