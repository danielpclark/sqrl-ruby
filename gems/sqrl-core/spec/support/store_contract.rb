# frozen_string_literal: true

# Behavioural contract every store set (memory, Redis, ActiveRecord, ...) must satisfy.
# It exercises the three interfaces exactly as SQRL::Server::Handler uses them.
#
#   RSpec.describe SQRL::Server::Memory do
#     let(:stores) { described_class.stores }
#     it_behaves_like "a SQRL store set"
#   end
RSpec.shared_examples "a SQRL store set" do
  let(:now) { Time.at(Time.now.to_i) }
  let(:idk_a) { "\x01".b * 32 }
  let(:idk_b) { "\x02".b * 32 }
  let(:suk) { "\x03".b * 32 }
  let(:vuk) { "\x04".b * 32 }

  def issue(nut, pending_login_id: "pl-1", expires_at: now + 300, bound_idk: nil, ip: "203.0.113.1")
    stores.nuts.issue(nut: nut, pending_login_id: pending_login_id, expected_server: "c2VydmVy",
                      ip: ip, bound_idk: bound_idk, expires_at: expires_at)
  end

  describe "nuts" do
    it "issues a record and consumes it exactly once" do
      record = issue("n1", bound_idk: idk_a)
      expect(record.nut).to eq("n1")
      expect(record).not_to be_used

      consumed = stores.nuts.consume("n1", now: now)
      expect(consumed.pending_login_id).to eq("pl-1")
      expect(consumed.expected_server).to eq("c2VydmVy")
      expect(consumed.ip).to eq("203.0.113.1")
      expect(consumed.bound_idk).to eq(idk_a)
      expect(consumed.bound_idk.encoding).to eq(Encoding::BINARY)
      expect(consumed.expires_at.to_i).to eq((now + 300).to_i)

      expect(stores.nuts.consume("n1", now: now)).to be_nil
      expect(stores.nuts.consume("unknown", now: now)).to be_nil
    end

    it "keeps a nil binding" do
      issue("n2")
      expect(stores.nuts.consume("n2", now: now).bound_idk).to be_nil
    end

    it "refuses an expired nut" do
      issue("n3", expires_at: now - 1)
      expect(stores.nuts.consume("n3", now: now)).to be_nil
    end

    it "lets exactly one of many concurrent consumers win" do
      issue("race")
      winners = Array.new(8) { Thread.new { stores.nuts.consume("race", now: now) } }.map(&:value)
      expect(winners.compact.size).to eq(1)
    end

    it "prunes used and expired nuts without touching live ones" do
      issue("live")
      issue("old", expires_at: now - 10)
      issue("used")
      stores.nuts.consume("used", now: now)
      stores.nuts.prune!(now)
      expect(stores.nuts.consume("live", now: now)).not_to be_nil
      expect(stores.nuts.consume("old", now: now)).to be_nil
      expect(stores.nuts.consume("used", now: now)).to be_nil
    end
  end

  describe "identities" do
    it "creates, finds, updates and removes" do
      expect(stores.identities.find(idk_a)).to be_nil
      created = stores.identities.create(idk: idk_a, suk: suk, vuk: vuk, disabled: false, sqrlonly: true,
                                         hardlock: false, ins: "aW5z", logins: 1, user_ref: "User:7")
      expect(created.idk).to eq(idk_a)

      found = stores.identities.find(idk_a)
      expect(found.idk).to eq(idk_a)
      expect(found.idk.encoding).to eq(Encoding::BINARY)
      expect(found.suk).to eq(suk)
      expect(found.vuk).to eq(vuk)
      expect(found).not_to be_disabled
      expect(found).to be_sqrlonly
      expect(found).not_to be_hardlock
      expect(found.ins).to eq("aW5z")
      expect(found.logins).to eq(1)
      expect(found.user_ref).to eq("User:7")

      updated = stores.identities.update(idk_a, disabled: true, logins: 2, ins: nil, user_ref: nil)
      expect(updated).to be_disabled
      expect(updated.logins).to eq(2)
      expect(updated.ins).to be_nil
      expect(updated.user_ref).to be_nil
      expect(stores.identities.find(idk_a)).to be_disabled
      expect(stores.identities.update(idk_b, disabled: true)).to be_nil

      removed = stores.identities.remove(idk_a)
      expect(removed.idk).to eq(idk_a)
      expect(stores.identities.find(idk_a)).to be_nil
      expect(stores.identities.remove(idk_a)).to be_nil
    end

    it "refuses to create the same identity twice" do
      stores.identities.create(idk: idk_a, suk: suk, vuk: vuk)
      expect { stores.identities.create(idk: idk_a, suk: suk, vuk: vuk) }.to raise_error(ArgumentError)
    end

    it "re-keys: the account moves, the old key is superseded, the indexed secret follows" do
      stores.identities.create(idk: idk_a, suk: suk, vuk: vuk, logins: 3, ins: "old", user_ref: "User:1",
                               sqrlonly: true)
      new_suk = "\x05".b * 32
      new_vuk = "\x06".b * 32
      rekeyed = stores.identities.rekey(idk_a, idk_b, suk: new_suk, vuk: new_vuk, ins: "new")
      expect(rekeyed.idk).to eq(idk_b)
      expect(rekeyed.suk).to eq(new_suk)
      expect(rekeyed.vuk).to eq(new_vuk)
      expect(rekeyed.ins).to eq("new")
      expect(rekeyed.logins).to eq(3)
      expect(rekeyed.user_ref).to eq("User:1")
      expect(rekeyed).to be_sqrlonly

      expect(stores.identities.find(idk_a)).to be_nil
      expect(stores.identities.find(idk_b).suk).to eq(new_suk)
      expect(stores.identities.superseded?(idk_a)).to be(true)
      expect(stores.identities.superseded?(idk_b)).to be(false)
      expect(stores.identities.rekey(idk_a, "\x07".b * 32, suk: suk, vuk: vuk, ins: nil)).to be_nil
    end

    it "re-keys with a nil indexed secret" do
      stores.identities.create(idk: idk_a, suk: suk, vuk: vuk, ins: "old")
      expect(stores.identities.rekey(idk_a, idk_b, suk: suk, vuk: vuk, ins: nil).ins).to be_nil
    end
  end

  describe "pending logins" do
    it "creates, finds and updates" do
      login = stores.pending_logins.create("pl-1", ip: "203.0.113.1", return_to: "/after", expires_at: now + 300,
                                                   link_user_ref: "User:9", created_at: now)
      expect(login.id).to eq("pl-1")
      expect(login).not_to be_authenticated

      found = stores.pending_logins.find("pl-1")
      expect(found.ip).to eq("203.0.113.1")
      expect(found.return_to).to eq("/after")
      expect(found.link_user_ref).to eq("User:9")
      expect(found.expires_at.to_i).to eq((now + 300).to_i)
      expect(found.created_at.to_i).to eq(now.to_i)
      expect(found.ip_matched).to be(false)
      expect(found).not_to be_asked
      expect(found).not_to be_expired(now)
      expect(found).to be_expired(now + 301)
      expect(stores.pending_logins.find("missing")).to be_nil

      updated = stores.pending_logins.update("pl-1", authenticated_idk: idk_a, authenticated_at: now,
                                                     ip_matched: true, btn: 2, asked: true, last_command: :ident)
      expect(updated).to be_authenticated
      expect(updated.authenticated_idk).to eq(idk_a)
      expect(updated.authenticated_idk.encoding).to eq(Encoding::BINARY)
      expect(updated.authenticated_at.to_i).to eq(now.to_i)
      expect(updated.ip_matched).to be(true)
      expect(updated.btn).to eq(2)
      expect(updated).to be_asked
      expect(updated.last_command).to eq(:ident)

      again = stores.pending_logins.find("pl-1")
      expect(again.authenticated_idk).to eq(idk_a)
      expect(again.ip_matched).to be(true)
      expect(again.last_command).to eq(:ident)

      cleared = stores.pending_logins.update("pl-1", authenticated_idk: nil, authenticated_at: nil)
      expect(cleared).not_to be_authenticated
      expect(stores.pending_logins.update("missing", btn: 1)).to be_nil
    end

    it "claims a CPS token exactly once" do
      stores.pending_logins.create("pl-2", ip: "1.1.1.1", return_to: nil, expires_at: now + 300)
      stores.pending_logins.update("pl-2", authenticated_idk: idk_a, cps_token: "tok-1",
                                           cps_token_expires_at: now + 60)
      expect(stores.pending_logins.claim_cps_token("nope", now: now)).to be_nil
      expect(stores.pending_logins.claim_cps_token("", now: now)).to be_nil
      expect(stores.pending_logins.claim_cps_token(nil, now: now)).to be_nil

      claimed = stores.pending_logins.claim_cps_token("tok-1", now: now)
      expect(claimed.id).to eq("pl-2")
      expect(claimed.authenticated_idk).to eq(idk_a)
      expect(claimed.cps_token).to be_nil

      expect(stores.pending_logins.claim_cps_token("tok-1", now: now)).to be_nil
      expect(stores.pending_logins.find("pl-2").cps_token).to be_nil
    end

    it "lets exactly one of many concurrent claimers win" do
      stores.pending_logins.create("pl-race", ip: "1.1.1.1", return_to: nil, expires_at: now + 300)
      stores.pending_logins.update("pl-race", authenticated_idk: idk_a, cps_token: "tok-race",
                                              cps_token_expires_at: now + 60)
      winners = Array.new(8) { Thread.new { stores.pending_logins.claim_cps_token("tok-race", now: now) } }.map(&:value)
      expect(winners.compact.size).to eq(1)
    end

    it "refuses an expired token and clears it" do
      stores.pending_logins.create("pl-3", ip: "1.1.1.1", return_to: nil, expires_at: now + 300)
      stores.pending_logins.update("pl-3", authenticated_idk: idk_a, cps_token: "tok-3",
                                           cps_token_expires_at: now - 1)
      expect(stores.pending_logins.claim_cps_token("tok-3", now: now)).to be_nil
      expect(stores.pending_logins.find("pl-3").cps_token).to be_nil
    end

    it "replaces a token when a new one is issued" do
      stores.pending_logins.create("pl-4", ip: "1.1.1.1", return_to: nil, expires_at: now + 300)
      stores.pending_logins.update("pl-4", cps_token: "first", cps_token_expires_at: now + 60)
      stores.pending_logins.update("pl-4", cps_token: "second", cps_token_expires_at: now + 60)
      expect(stores.pending_logins.claim_cps_token("first", now: now)).to be_nil
      expect(stores.pending_logins.claim_cps_token("second", now: now)&.id).to eq("pl-4")
    end

    it "prunes expired pending logins" do
      stores.pending_logins.create("fresh", ip: "1.1.1.1", return_to: nil, expires_at: now + 300)
      stores.pending_logins.create("stale", ip: "1.1.1.1", return_to: nil, expires_at: now - 1)
      stores.pending_logins.prune!(now)
      expect(stores.pending_logins.find("fresh")).not_to be_nil
      expect(stores.pending_logins.find("stale")).to be_nil
    end
  end
end
