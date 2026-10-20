# frozen_string_literal: true

RSpec.describe SQRL::Identity do
  it "identity lock round-trips: a URSK signature verifies under the VUK" do
    iuk = "\x2A" * 32
    id = SQRL::UnlockedIdentity.from_iuk(iuk)
    lock = id.make_lock
    ursk = described_class.unlock_request_seed(iuk, lock.suk)
    sig = SQRL::Crypto.ed25519_sign(ursk, "unlock me")
    expect(SQRL::Crypto.ed25519_verify(lock.vuk, "unlock me", sig)).to be(true)

    wrong = described_class.unlock_request_seed("\x2B" * 32, lock.suk)
    expect(SQRL::Crypto.ed25519_verify(lock.vuk, "unlock me", SQRL::Crypto.ed25519_sign(wrong, "unlock me"))).to be(false)
  end

  it "derives deterministic locks from a given RLK" do
    ilk = described_class.ilk_from_iuk("\x01" * 32)
    a = described_class.make_server_lock(ilk, "\x05" * 32)
    b = described_class.make_server_lock(ilk, "\x05" * 32)
    expect(a).to eq(b)
    expect(described_class.make_server_lock(ilk)).not_to eq(a)
  end

  it "derives the indexed secret from the site seed" do
    seed = "\x09" * 32
    ink = SQRL::Crypto.enhash(seed)
    expect(described_class.indexed_secret(seed, "0")).to eq(SQRL::Crypto.hmac_sha256(ink, "0"))
  end

  describe SQRL::UnlockedIdentity do
    it "site keys differ per site and identity" do
      a = described_class.from_iuk("\x01" * 32)
      b = described_class.from_iuk("\x02" * 32)
      expect(a.site_public_key("example.com")).not_to eq(a.site_public_key("example.org"))
      expect(a.site_public_key("example.com")).not_to eq(b.site_public_key("example.com"))
      expect(a.site_public_key("example.com")).to eq(a.site_public_key("example.com"))
    end

    it "derives previous identity keys" do
      old_iuk = "\x05" * 32
      old = described_class.from_iuk(old_iuk)
      new = described_class.from_iuk("\x06" * 32, [old_iuk])
      expect(new.previous_count).to eq(1)
      expect(new.previous_site_public_key(0, "example.com")).to eq(old.site_public_key("example.com"))
      expect(new.previous_site_public_key(1, "example.com")).to be_nil
      expect(new.previous_unlock_request_seed(0, "\x07" * 32))
        .to eq(SQRL::Identity.unlock_request_seed(old_iuk, "\x07" * 32))
      expect(new.previous_unlock_request_seed(3, "\x07" * 32)).to be_nil
    end

    it "recognises its own IUK and hides key material from inspect" do
      iuk = "\x08" * 32
      id = described_class.from_iuk(iuk)
      expect(id.matches_iuk?(iuk)).to be(true)
      expect(id.matches_iuk?("\x09" * 32)).to be(false)
      expect(id.fingerprint).to match(/\A[0-9a-f]{16}\z/)
      expect(id.inspect).not_to include(SQRL::Util.hex_encode(id.imk))
    end

    it "validates key sizes" do
      expect { described_class.new("short", "x" * 32) }.to raise_error(ArgumentError)
    end
  end
end
