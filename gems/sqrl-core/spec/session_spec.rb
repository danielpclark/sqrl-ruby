# frozen_string_literal: true

RSpec.describe SQRL::Session do
  def b64(str) = SQRL::Util.b64u_encode(str)
  def reply(text) = b64(text)

  let(:identity) { SQRL::UnlockedIdentity.from_iuk("\x01" * 32) }
  let(:url) { SQRL::URL.parse("sqrl://example.com/cli.sqrl?nut=n1") }

  it "builds a well-formed first query" do
    s = described_class.new(identity, url)
    req = s.query
    expect(req.url).to eq("https://example.com/cli.sqrl?nut=n1")
    expect(req.client_text).to start_with("ver=1\r\ncmd=query\r\nidk=")
    expect(req.client_text).to include("opt=suk\r\n")
    expect(req.client_text).not_to include("pidk=")
    expect(req.body).to include("&server=#{b64('sqrl://example.com/cli.sqrl?nut=n1')}&ids=")
    expect(req.body).not_to include("&pids=")
    expect(req.command).to eq(:query)
    expect(s.last_command).to eq(:query)
    expect(s.state).to eq(:no_response)
    # ident before a query is refused
    expect { s.ident }.to raise_error(SQRL::ProtocolError)
    expect { s.disable }.to raise_error(SQRL::ProtocolError)
    expect { s.enable }.to raise_error(SQRL::ProtocolError)
    expect { s.remove }.to raise_error(SQRL::ProtocolError)
  end

  it "accepts a URL string" do
    s = described_class.new(identity, "sqrl://example.com/cli.sqrl?nut=n1")
    expect(s.url).to eq(url)
    expect(s.idk_b64).to eq(b64(s.idk))
  end

  it "signs the client and server parameters with the per-site key" do
    s = described_class.new(identity, url)
    req = s.query
    client_b64, server_b64, ids_b64 = req.body.scan(/(?:client|server|ids)=([^&]+)/).flatten
    msg = client_b64 + server_b64
    expect(SQRL::Crypto.ed25519_verify(s.idk, msg, SQRL::Util.b64u_decode(ids_b64))).to be(true)
    expect(SQRL::Crypto.ed25519_verify(s.idk, "#{msg}x", SQRL::Util.b64u_decode(ids_b64))).to be(false)
  end

  it "never carries sqrlonly or hardlock with remove" do
    s = described_class.new(identity, url, options: SQRL::ClientOptions.new(sqrlonly: true, hardlock: true, cps: true))
    q = s.query
    expect(q.client_text).to include("opt=sqrlonly~hardlock~cps~suk\r\n")
    suk = b64("\x09" * 32)
    s.feed(reply("ver=1\r\nnut=a\r\ntif=5\r\nqry=/cli.sqrl?nut=a\r\nsuk=#{suk}\r\n"))
    r = s.remove("\x01" * 32)
    expect(r.client_text).to include("opt=cps~suk\r\n")
    expect(r.body).to include("&urs=")
    i = s.ident
    expect(i.client_text).to include("opt=sqrlonly~hardlock~cps~suk\r\n")
    expect(i.url).to eq("https://example.com/cli.sqrl?nut=a")
  end

  it "aborts on undefined TIF bits" do
    s = described_class.new(identity, url)
    expect { s.feed(reply("ver=1\r\nnut=a\r\ntif=405\r\nqry=/cli.sqrl?nut=a\r\n")) }.to raise_error(SQRL::ProtocolError)
    expect(s.feed(reply("ver=1\r\nnut=a\r\ntif=3ff\r\nqry=/cli.sqrl?nut=a\r\n"))).to be_a(SQRL::ServerResponse)
  end

  it "rejects a qry pointing elsewhere" do
    s = described_class.new(identity, url)
    expect { s.feed(reply("ver=1\r\nnut=x\r\ntif=0\r\nqry=https://evil.example/cli.sqrl?nut=x\r\n")) }
      .to raise_error(SQRL::ProtocolError)
    expect { s.feed(reply("ver=1\r\nnut=x\r\ntif=0\r\nqry=//evil.example/cli.sqrl?nut=x\r\n")) }
      .to raise_error(SQRL::ProtocolError)
    expect(s.last_response).to be_nil
  end

  it "only honours an ask in query replies with id match, and pins button URLs" do
    s = described_class.new(identity, url)
    ask = SQRL::Ask.new(message: "Sure?", buttons: [{ label: "Go", url: "extra/confirm.html" }]).to_wire
    s.query
    # unknown identity: ignored
    s.feed(reply("ver=1\r\nnut=a\r\ntif=4\r\nqry=/cli.sqrl?nut=a\r\nask=#{ask}\r\n"))
    expect(s.pending_ask).to be_nil
    # known identity: honoured, and the button URL is pinned to this origin
    s.query
    s.feed(reply("ver=1\r\nnut=b\r\ntif=5\r\nqry=/cli.sqrl?nut=b\r\nask=#{ask}\r\n"))
    expect(s.pending_ask).to be_a(SQRL::Ask)
    expect(s.ask_button_url(0)).to eq("https://example.com/extra/confirm.html")
    expect(s.ask_button_url(1)).to be_nil
    s.set_button(1)
    expect(s.pending_ask).to be_nil
    i = s.ident
    expect(i.client_text).to include("btn=1\r\n")
    # the button is sent once
    expect(s.ident.client_text).not_to include("btn=")
    # an ask in a non-query reply is ignored
    s.feed(reply("ver=1\r\nnut=c\r\ntif=5\r\nqry=/cli.sqrl?nut=c\r\nask=#{ask}\r\n"))
    expect(s.pending_ask).to be_nil
    # a failed query reply does not pose the question either
    s.query
    s.feed(reply("ver=1\r\nnut=d\r\ntif=41\r\nqry=/cli.sqrl?nut=d\r\nask=#{ask}\r\n"))
    expect(s.pending_ask).to be_nil
  end

  it "clamps the button value" do
    s = described_class.new(identity, url)
    s.set_button(9)
    expect(s.query.client_text).to include("btn=2\r\n")
  end

  it "reads the cancel URL from the URL or the server's can=" do
    can = b64("https://example.com/login")
    u = SQRL::URL.parse("sqrl://example.com/cli.sqrl?nut=n1&can=#{can}")
    s = described_class.new(identity, u)
    expect(s.cancel_url).to eq("https://example.com/login")
    s.feed(reply("ver=1\r\nnut=a\r\ntif=5\r\nqry=/cli.sqrl?nut=a\r\ncan=/bye?x=1\r\n"))
    expect(s.cancel_url).to eq("https://example.com/bye?x=1")
    expect(described_class.new(identity, url).cancel_url).to be_nil
  end

  it "drops a cancel URL that points away from the site" do
    can = b64("https://evil.example/phish")
    u = SQRL::URL.parse("sqrl://example.com/cli.sqrl?nut=n1&can=#{can}")
    s = described_class.new(identity, u)
    expect(s.cancel_url).to be_nil
    s.feed(reply("ver=1\r\nnut=a\r\ntif=5\r\nqry=/cli.sqrl?nut=a\r\ncan=http://example.com/bye\r\n"))
    expect(s.cancel_url).to be_nil
  end

  it "validates the CPS url host" do
    s = described_class.new(identity, url)
    expect(s.cps_url).to be_nil
    s.feed(reply("ver=1\r\nnut=x\r\ntif=1\r\nqry=/cli.sqrl?nut=x\r\nurl=https://evil.example/\r\n"))
    expect { s.cps_url }.to raise_error(SQRL::ProtocolError)
    s.feed(reply("ver=1\r\nnut=x\r\ntif=1\r\nqry=/cli.sqrl?nut=x\r\nurl=/loggedin?s=1\r\n"))
    expect(s.cps_url).to eq("https://example.com/loggedin?s=1")
    s.feed(reply("ver=1\r\nnut=x\r\ntif=1\r\nqry=/cli.sqrl?nut=x\r\nurl=https://EXAMPLE.com:8443/ok\r\n"))
    expect(s.cps_url).to eq("https://EXAMPLE.com:8443/ok")
  end

  it "derives states from the TIF" do
    s = described_class.new(identity, url)
    {
      "5" => :known, "d" => :known, "2" => :previous_known, "4" => :unknown, "60" => :transient,
      "200" => :superseded, "c0" => :failed, "140" => :failed, "50" => :failed, "40" => :failed, "41" => :failed
    }.each do |tif, kind|
      s.feed(reply("ver=1\r\nnut=a\r\ntif=#{tif}\r\nqry=/x\r\n"))
      expect(s.state.kind).to eq(kind), "tif=#{tif}"
    end
    s.feed(reply("ver=1\r\nnut=a\r\ntif=d\r\nqry=/x\r\n"))
    expect(s.state).to be_disabled
    expect(s.state).to eq(SQRL::Session::State.new(kind: :known, disabled: true))
    s.feed(reply("ver=1\r\nnut=a\r\ntif=40\r\nqry=/x\r\n"))
    expect(s).to be_ip_check_failed
    expect(s.state.message).to match(/IP address/)
    s.feed(reply("ver=1\r\nnut=a\r\ntif=41\r\nqry=/x\r\n"))
    expect(s).not_to be_ip_check_failed
  end

  it "walks previous identities" do
    old_iuk = "\x05" * 32
    older_iuk = "\x06" * 32
    id = SQRL::UnlockedIdentity.from_iuk("\x07" * 32, [old_iuk, older_iuk])
    s = described_class.new(id, url)
    expect(s).to have_previous
    expect(s.previous_count).to eq(2)
    expect(s.previous_index).to eq(0)
    q = s.query
    pidk = q.client_text[/pidk=([^\r]+)/, 1]
    expect(pidk).to eq(b64(SQRL::UnlockedIdentity.from_iuk(old_iuk).site_public_key("example.com")))
    expect(q.body).to include("&pids=")
    expect(s.try_next_previous).to be(true)
    q = s.query
    expect(q.client_text[/pidk=([^\r]+)/, 1])
      .to eq(b64(SQRL::UnlockedIdentity.from_iuk(older_iuk).site_public_key("example.com")))
    expect(s.try_next_previous).to be(false)
  end

  it "re-keys when only a previous identity matched" do
    old_iuk = "\x05" * 32
    id = SQRL::UnlockedIdentity.from_iuk("\x07" * 32, [old_iuk])
    suk = "\x09" * 32
    lock = SQRL::Identity.make_server_lock(id.ilk, "\x11" * 32)
    s = described_class.new(id, url, lock_factory: ->(_ilk) { lock })
    s.query
    expect { s.feed(reply("ver=1\r\nnut=a\r\ntif=2\r\nqry=/x\r\n")) && s.ident }
      .to raise_error(SQRL::ProtocolError, /no suk/)
    s.feed(reply("ver=1\r\nnut=a\r\ntif=2\r\nqry=/x\r\nsuk=#{b64(suk)}\r\n"))
    i = s.ident
    expect(i.client_text).to include("pidk=", "suk=#{b64(lock.suk)}", "vuk=#{b64(lock.vuk)}")
    expect(i.body).to include("&pids=", "&urs=")
    urs = SQRL::Util.b64u_decode(i.body[/&urs=([^&]+)/, 1])
    msg = i.body.scan(/(?:client|server)=([^&]+)/).flatten.join
    # the urs verifies under the VUK that the old identity gave the server
    old_vuk = SQRL::Crypto.ed25519_public(SQRL::Crypto.x25519(old_iuk, suk))
    expect(SQRL::Crypto.ed25519_verify(old_vuk, msg, urs)).to be(true)
    # disable/enable/remove re-key too, without needing the current IUK
    expect(s.disable.body).to include("&urs=")
    expect(s.enable.body).to include("&urs=")
    expect(s.remove.body).to include("&urs=")
  end

  it "requires the IUK for enable/remove on a current match" do
    s = described_class.new(identity, url)
    s.query
    s.feed(reply("ver=1\r\nnut=a\r\ntif=d\r\nqry=/x\r\n"))
    expect { s.enable }.to raise_error(SQRL::ProtocolError, /suk/)
    s.feed(reply("ver=1\r\nnut=a\r\ntif=d\r\nqry=/x\r\nsuk=#{b64("\x09" * 32)}\r\n"))
    expect { s.enable }.to raise_error(SQRL::ProtocolError, /rescue code/)
    e = s.enable("\x01" * 32)
    expect(e.client_text).not_to include("pidk=", "suk=")
    expect(e.body).to include("&urs=")
    expect(e.body).not_to include("&pids=")
  end

  it "sends ins and pins when the server poses a sin" do
    old_iuk = "\x05" * 32
    id = SQRL::UnlockedIdentity.from_iuk("\x07" * 32, [old_iuk])
    s = described_class.new(id, url)
    s.query
    s.feed(reply("ver=1\r\nnut=a\r\ntif=4\r\nqry=/x\r\nsin=0\r\n"))
    q = s.query
    ins = q.client_text[/ins=([^\r]+)/, 1]
    pins = q.client_text[/pins=([^\r]+)/, 1]
    expect(ins).to eq(b64(SQRL::Identity.indexed_secret(id.site_seed("example.com"), "0")))
    expect(pins).to eq(b64(SQRL::Identity.indexed_secret(
                            SQRL::UnlockedIdentity.from_iuk(old_iuk).site_seed("example.com"), "0"
                          )))
    i = s.ident
    expect(i.client_text).to include("ins=")
    expect(i.client_text).not_to include("pins=")
  end

  it "uses the previous response verbatim as the next server parameter" do
    s = described_class.new(identity, url)
    s.query
    body = reply("ver=1\r\nnut=a\r\ntif=4\r\nqry=/cli.sqrl?nut=a\r\n")
    s.feed(" #{body}\r\n")
    expect(s.ident.body).to include("&server=#{body}&")
  end

  it "applies Alt-IDs" do
    plain = described_class.new(identity, url)
    alt = described_class.new(identity, url, alt_id: "work")
    expect(plain.idk).not_to eq(alt.idk)
    expect(alt.idk).to eq(identity.site_public_key("example.com\0work".b))
  end

  it "exposes copies of its options" do
    s = described_class.new(identity, url, options: SQRL::ClientOptions.new(cps: true))
    o = s.options
    o.cps = false
    expect(s.options).to be_cps
    s.options = o
    expect(s.options).not_to be_cps
    expect(s.inspect).to include("example.com")
  end
end
