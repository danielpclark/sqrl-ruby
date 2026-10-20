# frozen_string_literal: true

# SQRL.log excerpts from "SQRL Cryptography" v1.04, "SQRL Cryptography Test Vectors": the
# Spec-Vectors-Identity logging in to sqrl.grc.com. Everything the client sends is
# deterministic, so the whole POST body must match GRC's client byte for byte.
RSpec.describe "protocol test vectors" do
  SPEC_IMK_HEX = "2E471E106D758F3C7B242C8A4A0513A7192D8EDDB917BDD019F19E38ED292BA8"

  def b64(str) = SQRL::Util.b64u_encode(str)

  it "reproduces the query and ident transactions from SQRL.log" do
    imk = SQRL::Util.hex_decode(SPEC_IMK_HEX)
    identity = SQRL::UnlockedIdentity.new(imk, "\x00" * 32)
    url = SQRL::URL.parse("sqrl://sqrl.grc.com/cli.sqrl?nut=fXkb4MBToCm7&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw")
    expect(url.site_key).to eq("sqrl.grc.com")
    expect(url.cancel_url).to eq("https://sqrl.grc.com/demo")

    s = SQRL::Session.new(identity, url, options: SQRL::ClientOptions.new(cps: true))
    q = s.query
    expect(q.url).to eq("https://sqrl.grc.com/cli.sqrl?nut=fXkb4MBToCm7&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw")
    expect(q.client_text).to eq("ver=1\r\ncmd=query\r\nidk=2jgB-cR-EnlYglPdGToOucKYI6CD6sUqf4k9MtkuiXs\r\nopt=cps~suk\r\n")
    expect(q.body).to start_with("client=dmVyPTENCmNtZD1xdWVyeQ0KaWRrPTJqZ0ItY1ItRW5sWWdsUGRHVG9PdWNLWUk2Q0Q2c1VxZjRrOU10a3Vp")
    expect(q.body).to include("&server=c3FybDovL3NxcmwuZ3JjLmNvbS9jbGkuc3FybD9udXQ9ZlhrYjRNQlRvQ203JmNhbj1hSFIwY0hNNkx5OXpj")
    expect(q.body).to end_with("&ids=qXFikmg_jZQJ7GjKCA_zBwzras2QyQAwWw2s80ZcUHmLLBUN5_hPuFtB6ZoV5wUcNs5XmSrqg1FQwGA6RlVBAQ")

    # Server reply 1 (decoded in the log; ContentLength 151 is the base64url length).
    reply1 = b64("ver=1\r\nnut=1WM9lfF1ST-z\r\ntif=5\r\nqry=/cli.sqrl?nut=1WM9lfF1ST-z\r\n" \
                 "suk=BMFDm7bPlsQojuJsoDTvlS1McnwgScvktF84vLjscGk\r\n")
    expect(reply1.length).to eq(151)
    expect(reply1).to start_with("dmVyPTENCm51dD0xV005bGZGMVNULXoNCnRpZj01DQpxcnk9L2NsaS5zcXJsP251dD0xV005bGZGMVNULXoN")
    r = s.feed(reply1)
    expect(r.tif).to be_id_match
    expect(r.tif).to be_ips_matched
    expect(b64(r.suk)).to eq("BMFDm7bPlsQojuJsoDTvlS1McnwgScvktF84vLjscGk")

    # Transaction 2: the ident, signed over the client text and the reply exactly as received.
    i = s.ident
    expect(i.url).to eq("https://sqrl.grc.com/cli.sqrl?nut=1WM9lfF1ST-z")
    expect(i.client_text).to eq("ver=1\r\ncmd=ident\r\nidk=2jgB-cR-EnlYglPdGToOucKYI6CD6sUqf4k9MtkuiXs\r\nopt=cps~suk\r\n")
    expect(i.body).to start_with("client=dmVyPTENCmNtZD1pZGVudA0KaWRrPTJqZ0ItY1ItRW5sWWdsUGRHVG9PdWNLWUk2Q0Q2c1VxZjRrOU10a3Vp")
    expect(i.body).to end_with("&ids=kQI05IpE_cu4u0mf7jymbap09hmS6ZCWjBGKUYnSNVRTXPbreTvDWHKNbSkUlQT2bx3wXwW3cCLBD0Qedd64AA")

    # Server reply 2 with the CPS url.
    reply2 = b64("ver=1\r\nnut=BEFAI1tJYfBm\r\ntif=5\r\nqry=/cli.sqrl?nut=BEFAI1tJYfBm\r\n" \
                 "suk=BMFDm7bPlsQojuJsoDTvlS1McnwgScvktF84vLjscGk\r\n" \
                 "url=https://sqrl.grc.com/auth.test?4hVTe9LGHhMTuxz_mm6vRc_q\r\n")
    expect(reply2.length).to eq(232)
    s.feed(reply2)
    expect(s.cps_url).to eq("https://sqrl.grc.com/auth.test?4hVTe9LGHhMTuxz_mm6vRc_q")
  end
end
