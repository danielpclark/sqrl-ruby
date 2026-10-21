# frozen_string_literal: true

require_relative "support/flow_helpers"

# Server behaviours pinned to Steve Gibson's final word: the December 2019 "SQRL On The Wire"
# v1.07 document and his later rulings in the grc.sqrl newsgroup (cited by article number).
RSpec.describe "SQRL::Server conformance to Gibson's rulings" do
  let(:handler) { new_handler }
  let(:iuk) { 7.chr * 32 }
  let(:id) { identity(7) }

  def create!(handler, identity)
    _, s = new_session(handler, identity)
    exchange(handler, s, s.query)
    exchange(handler, s, s.ident)
    s
  end

  describe "suk" do
    # "Whenever 'suk' is present in the client's opt= value list, the server will return its saved
    # SUK in its reply ... it *MUST* also always provide it when the client's query requests it."
    # (grc.sqrl:12289, 9 Jan 2016; On The Wire v1.07 p.14.) GRC's reference client sends
    # opt=cps~suk with every command and GRC's server answers every one of them with suk=.
    it "is returned in the reply to every command the client requests it with, not only query" do
      create!(handler, id)
      _, s = new_session(handler, id, SQRL::ClientOptions.new(cps: true))
      exchange(handler, s, s.query)
      expect(s.last_response.suk).not_to be_nil
      exchange(handler, s, s.ident)
      expect(s.last_response.suk).not_to be_nil, "ident reply lacks suk although opt=suk was sent"

      _, s = new_session(handler, id)
      exchange(handler, s, s.query)
      exchange(handler, s, s.disable)
      expect(s.last_response.suk).not_to be_nil, "disable reply lacks suk"

      _, s = new_session(handler, id)
      exchange(handler, s, s.query)
      exchange(handler, s, s.enable(iuk))
      expect(s.last_response.suk).not_to be_nil, "enable reply lacks suk"
    end

    it "is not returned to a client that did not ask for it on a healthy, current identity" do
      create!(handler, id)
      login = handler.new_login_url(ip: FlowHelpers::IP)
      s = SQRL::Session.new(id, login.url)
      # SQRL::Session always asks for the suk (like GRC's client); build the bare request by hand
      q = s.query
      client = SQRL::Util.b64u_decode(q.body[/client=([^&]+)/, 1]).sub("opt=suk\r\n", "")
      client_b64 = SQRL::Util.b64u_encode(client)
      server_b64 = q.body[/server=([^&]+)/, 1]
      sig = SQRL::Crypto.ed25519_sign(id.site_seed(SQRL::URL.parse(login.url).site_key_bytes), client_b64 + server_b64)
      body = "client=#{client_b64}&server=#{server_b64}&ids=#{SQRL::Util.b64u_encode(sig)}"
      r = handler.handle(nut: nut_of(q), body: body, ip: FlowHelpers::IP)
      expect(r.tif).to be_id_match
      expect(SQRL::ServerResponse.parse(r.body).suk).to be_nil
    end

    it "is always returned for a disabled account, even unasked" do
      create!(handler, id)
      _, s = new_session(handler, id)
      exchange(handler, s, s.query)
      exchange(handler, s, s.disable)
      expect(s.last_response.tif).to be_sqrl_disabled
      expect(s.last_response.suk).not_to be_nil
    end
  end

  describe "cps url=" do
    # "This parameter must be provided by the server in its response to any command, other than
    # query, when the SQRL client includes the opt=cps option" (On The Wire v1.07 p.14). The
    # waiting browser is otherwise left with only the can= cancel redirect.
    it "is returned for a disable issued in CPS mode" do
      create!(handler, id)
      _, s = new_session(handler, id, SQRL::ClientOptions.new(cps: true))
      exchange(handler, s, s.query)
      r = exchange(handler, s, s.disable)
      expect(r.tif).to be_sqrl_disabled
      expect(r.cps_url).to start_with("https://example.com/sqrl/callback?t=")
      expect(s.cps_url).to eq(r.cps_url)
      # the callback token exists but the pending login is not authenticated: nobody gets logged in
      claimed = handler.claim_cps(r.cps_url[/t=(.+)\z/, 1])
      expect(claimed).not_to be_nil
      expect(claimed).not_to be_authenticated
    end
  end

  describe "re-keying" do
    let(:old) { identity(4) }
    let(:new) { identity(5, [4]) }

    # "The TIF to be returned is modified to reflect the post update state. So 'Previous ID
    # Match' is turned off and 'Current ID Match' is turned on." (grc.sqrl:20273, 16 Aug 2018;
    # On The Wire v1.07 p.17; grc.sqrl:22934, 6 Sep 2019.)
    it "replies to the updating command with 0x01 set and 0x02 clear" do
      create!(handler, old)
      _, s = new_session(handler, new)
      r = exchange(handler, s, s.query)
      expect(r.tif.value & 0x03).to eq(0x02)
      r = exchange(handler, s, s.ident)
      expect(r.tif.value & 0x03).to eq(0x01)
      expect(r).to be_rekeyed
    end

    # "Any account disabled state (under the old key) is cleared so that the account can be
    # immediately used under the new key." (grc.sqrl:20273.) The urs under the previous VUK
    # carries the same rescue-code authority as an enable.
    it "clears a disabled state along with the key update" do
      create!(handler, old)
      _, s = new_session(handler, old)
      exchange(handler, s, s.query)
      exchange(handler, s, s.disable)
      expect(handler.stores.identities.find(s.idk)).to be_disabled

      _, s = new_session(handler, new)
      r = exchange(handler, s, s.query)
      expect(r.tif).to be_previous_id_match
      expect(r.tif).to be_sqrl_disabled
      r = exchange(handler, s, s.ident)
      expect(r.tif).to be_id_match
      expect(r.tif).not_to be_sqrl_disabled
      expect(r.tif).not_to be_error
      expect(r).to be_authenticated
      expect(handler.stores.identities.find(s.idk)).not_to be_disabled
    end

    # "the server must immediately fail that client query by returning a TIF of 0x240"
    # (On The Wire v1.07 p.18; grc.sqrl:23020, 13 Sep 2019).
    it "fails a superseded identity with exactly 0x240" do
      create!(handler, old)
      create!(handler, new)
      _, s = new_session(handler, old)
      r = exchange(handler, s, s.query)
      expect(r.tif.to_hex).to eq("240")
      r = exchange(handler, s, s.ident)
      expect(r.tif.to_hex).to eq("240")
      expect(r).not_to be_authenticated
    end
  end

  describe "sqrlonly / hardlock" do
    # "Servers that support this option MUST retain and honor the most recently received state of
    # this option as presented during the most recent successful non-query command. ... Its
    # absence from any valid non-query command should immediately reset the flag" (On The Wire
    # v1.07 p.7; grc.sqrl:15905, 4 Aug 2017).
    it "copies the flags from every successful non-query command" do
      _, s = new_session(handler, id, SQRL::ClientOptions.new(sqrlonly: true, hardlock: true))
      exchange(handler, s, s.query)
      exchange(handler, s, s.ident)
      expect(handler.stores.identities.find(s.idk)).to be_sqrlonly.and be_hardlock

      _, s = new_session(handler, id, SQRL::ClientOptions.new(sqrlonly: true))
      exchange(handler, s, s.query)
      exchange(handler, s, s.disable)
      stored = handler.stores.identities.find(s.idk)
      expect(stored).to be_sqrlonly
      expect(stored).not_to be_hardlock

      _, s = new_session(handler, id)
      exchange(handler, s, s.query)
      exchange(handler, s, s.enable(iuk))
      stored = handler.stores.identities.find(s.idk)
      expect(stored).not_to be_sqrlonly
      expect(stored).not_to be_hardlock
    end
  end

  describe "stale nuts" do
    # "In the case that two successive TIF errors exactly match, the SQRL client MUST abort the
    # transaction and ask the user to please refresh their login page" (grc.sqrl:23543, 23 Nov
    # 2019). A by-reference server therefore answers the retry exactly as it answered the stale nut.
    it "answers the retry of a stale nut with the identical transient error" do
      s = SQRL::Session.new(id, "sqrl://example.com/cli.sqrl?nut=stale")
      first = post(handler, s.query)
      s.feed(first.body)
      second = post(handler, s.query)
      expect(first.tif).to be_transient_error
      expect(second.tif).to eq(first.tif)
    end
  end
end
