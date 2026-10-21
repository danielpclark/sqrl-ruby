# frozen_string_literal: true

RSpec.describe SQRL::Rails::Stores::ActiveRecord do
  let(:stores) { described_class.stores }
  let(:now) { Time.current }
  let(:idk) { "\x01" * 32 }
  let(:suk) { "\x02" * 32 }
  let(:vuk) { "\x03" * 32 }

  it_behaves_like "a SQRL store set"

  describe "NutStore" do
    it "issues a nut and consumes it exactly once" do
      stores.nuts.issue(nut: "n1", pending_login_id: "p1", expected_server: "srv", ip: "1.2.3.4",
                        bound_idk: nil, expires_at: now + 60)
      record = stores.nuts.consume("n1", now: now)
      expect(record.pending_login_id).to eq("p1")
      expect(record.expected_server).to eq("srv")
      expect(record.used_at).not_to be_nil
      expect(stores.nuts.consume("n1", now: now)).to be_nil
    end

    it "refuses expired and unknown nuts and round-trips the bound idk" do
      stores.nuts.issue(nut: "old", pending_login_id: "p", expected_server: "s", ip: "i", bound_idk: idk,
                        expires_at: now - 1)
      expect(stores.nuts.consume("old", now: now)).to be_nil
      expect(stores.nuts.consume("missing", now: now)).to be_nil
      stores.nuts.issue(nut: "bound", pending_login_id: "p", expected_server: "s", ip: "i", bound_idk: idk,
                        expires_at: now + 10)
      expect(stores.nuts.consume("bound", now: now).bound_idk).to eq(idk)
    end

    it "prunes used and expired nuts" do
      stores.nuts.issue(nut: "a", pending_login_id: "p", expected_server: "s", ip: "i", bound_idk: nil,
                        expires_at: now - 1)
      stores.nuts.issue(nut: "b", pending_login_id: "p", expected_server: "s", ip: "i", bound_idk: nil,
                        expires_at: now + 100)
      stores.nuts.issue(nut: "c", pending_login_id: "p", expected_server: "s", ip: "i", bound_idk: nil,
                        expires_at: now + 100)
      stores.nuts.consume("c", now: now)
      stores.nuts.prune!(now)
      expect(SQRL::Rails::Nut.pluck(:nut)).to eq(["b"])
    end
  end

  describe "IdentityStore" do
    it "creates, finds, updates and removes identities with user references" do
      created = stores.identities.create(idk: idk, suk: suk, vuk: vuk, logins: 1, user_ref: "User:7")
      expect(created.idk).to eq(idk)
      found = stores.identities.find(idk)
      expect(found.suk).to eq(suk)
      expect(found.vuk).to eq(vuk)
      expect(found.user_ref).to eq("User:7")
      expect(found.logins).to eq(1)
      expect(stores.identities.find("\x09" * 32)).to be_nil

      updated = stores.identities.update(idk, disabled: true, logins: 2, ins: "abc", sqrlonly: true)
      expect(updated).to be_disabled
      expect(updated.logins).to eq(2)
      expect(updated.ins).to eq("abc")
      expect(updated).to be_sqrlonly
      row = SQRL::Rails::Identity.find_by(idk: SQRL::Util.b64u_encode(idk))
      expect(row.user_type).to eq("User")
      expect(row.user_id).to eq(7)

      expect(stores.identities.update(idk, user_ref: nil).user_ref).to be_nil
      expect(stores.identities.remove(idk).idk).to eq(idk)
      expect(stores.identities.find(idk)).to be_nil
      expect(stores.identities.remove(idk)).to be_nil
    end

    it "re-keys in place and leaves a superseded tombstone" do
      stores.identities.create(idk: idk, suk: suk, vuk: vuk, logins: 3, user_ref: "User:1", ins: "old")
      new_idk = "\x0A" * 32
      rekeyed = stores.identities.rekey(idk, new_idk, suk: "\x0B" * 32, vuk: "\x0C" * 32, ins: "new")
      expect(rekeyed.idk).to eq(new_idk)
      expect(rekeyed.logins).to eq(3)
      expect(rekeyed.user_ref).to eq("User:1")
      expect(rekeyed.ins).to eq("new")
      expect(stores.identities.find(idk)).to be_nil
      expect(stores.identities.superseded?(idk)).to be(true)
      expect(stores.identities.superseded?(new_idk)).to be(false)
      expect(stores.identities.find(new_idk).suk).to eq("\x0B" * 32)
      expect(stores.identities.rekey("\x0F" * 32, new_idk, suk: suk, vuk: vuk, ins: nil)).to be_nil
    end
  end

  describe "PendingLoginStore" do
    it "creates, updates and claims CPS tokens exactly once" do
      stores.pending_logins.create("p1", ip: "1.1.1.1", return_to: "/x", expires_at: now + 60, link_user_ref: "User:2")
      login = stores.pending_logins.find("p1")
      expect(login.return_to).to eq("/x")
      expect(login.link_user_ref).to eq("User:2")
      expect(login).not_to be_authenticated

      updated = stores.pending_logins.update("p1", authenticated_idk: idk, authenticated_at: now, btn: 1,
                                                   last_command: :ident, cps_token: "tok",
                                                   cps_token_expires_at: now + 30)
      expect(updated.authenticated_idk).to eq(idk)
      expect(updated.last_command).to eq(:ident)
      expect(updated.btn).to eq(1)

      claimed = stores.pending_logins.claim_cps_token("tok", now: now)
      expect(claimed.id).to eq("p1")
      expect(claimed.cps_token).to be_nil
      expect(stores.pending_logins.claim_cps_token("tok", now: now)).to be_nil
      expect(stores.pending_logins.find("p1").cps_token).to be_nil
    end

    it "treats an expired token as unclaimable and prunes expired logins" do
      stores.pending_logins.create("p2", ip: "i", return_to: nil, expires_at: now - 1)
      stores.pending_logins.update("p2", cps_token: "late", cps_token_expires_at: now - 1)
      expect(stores.pending_logins.claim_cps_token("late", now: now)).to be_nil
      expect(stores.pending_logins.find("p2").cps_token).to be_nil
      stores.pending_logins.prune!(now)
      expect(stores.pending_logins.find("p2")).to be_nil
      expect(stores.pending_logins.find(nil)).to be_nil
    end
  end

  it "passes the core handler flows end to end on ActiveRecord" do
    config = SQRL::Server::Config.new(host: "example.com", require_ip_match: false)
    handler = SQRL::Server::Handler.new(config: config, stores: stores)
    login = handler.new_login_url(ip: "9.9.9.9")
    session = SQRL::Session.new(identity, login.url, options: SQRL::ClientOptions.new(cps: true))
    req = session.query
    session.feed(handler.handle(nut: URI.parse(req.url).query[/nut=([^&]+)/, 1], body: req.body, ip: "9.9.9.9").body)
    expect(session.state).to eq(:unknown)
    req = session.ident
    result = handler.handle(nut: URI.parse(req.url).query[/nut=([^&]+)/, 1], body: req.body, ip: "9.9.9.9")
    expect(result).to be_authenticated
    expect(result).to be_created
    session.feed(result.body)
    expect(session.cps_url).to start_with("https://example.com/sqrl/callback?t=")
    # a CPS login is authenticated on the pending login but never reported to the browser poll
    expect(stores.pending_logins.find(login.pending_login_id)).to be_authenticated.and be_cps
    expect(handler.status(login.pending_login_id)[:authenticated]).to be(false)
    token = session.cps_url[/t=(.+)/, 1]
    expect(handler.claim_cps(token).id).to eq(login.pending_login_id)
    expect(handler.claim_cps(token)).to be_nil
  end
end
