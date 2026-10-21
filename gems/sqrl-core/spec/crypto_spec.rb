# frozen_string_literal: true

require "sqrl/test_vectors"

RSpec.describe SQRL::Crypto do
  def hex(bytes)
    SQRL::Util.hex_encode(bytes)
  end

  def unhex(text)
    SQRL::Util.hex_decode(text)
  end

  describe ".enscrypt_iterations", :slow do
    SQRL::TestVectors::ENSCRYPT.each do |password, salt_hex, iterations, expected|
      it "matches the published vector for #{password.inspect} / #{salt_hex.length / 2}-byte salt / #{iterations} iterations" do
        expect(hex(described_class.enscrypt_iterations(password, unhex(salt_hex), 9, iterations))).to eq(expected)
      end
    end

    it "reports progress after every iteration" do
      seen = []
      described_class.enscrypt_iterations("pw", "salt", 9, 3) { |n| seen << n }
      expect(seen).to eq([1, 2, 3])
    end

    it "treats an iteration count below one as one" do
      expect(described_class.enscrypt_iterations("pw", "salt", 9,
                                                 0)).to eq(described_class.enscrypt_iterations("pw", "salt", 9, 1))
    end
  end

  describe ".enscrypt_duration" do
    it "runs until the clock says the duration has elapsed and matches the iteration form" do
      t = 0
      clock = -> { t += 30 }
      key, iters = described_class.enscrypt_duration("pw", "salt", 9, 100, now_ms: clock)
      expect(iters).to be >= 2
      expect(described_class.enscrypt_iterations("pw", "salt", 9, iters)).to eq(key)
    end

    it "reports elapsed and total time" do
      t = 0
      seen = []
      described_class.enscrypt_duration("pw", "salt", 9, 50, now_ms: -> { t += 30 }) { |a, b| seen << [a, b] }
      expect(seen.last[1]).to eq(50)
      expect(seen.last[0]).to be >= 50
    end
  end

  describe ".enhash" do
    it "is deterministic and differs from a single SHA-256" do
      x = described_class.enhash("hello")
      expect(x).to eq(described_class.enhash("hello"))
      expect(x).not_to eq(described_class.sha256("hello"))
      expect(x.bytesize).to eq(32)
    end

    it "equals the XOR of 16 chained SHA-256 outputs" do
      cur = described_class.sha256("abc")
      acc = cur.bytes
      15.times do
        cur = described_class.sha256(cur)
        cur.bytes.each_with_index { |b, i| acc[i] ^= b }
      end
      expect(described_class.enhash("abc")).to eq(acc.pack("C*"))
    end
  end

  describe ".hmac_sha256" do
    it "matches a known RFC 4231 vector" do
      key = "\x0b" * 20
      expect(hex(described_class.hmac_sha256(key, "Hi There")))
        .to eq("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    end
  end

  describe "AES-256-GCM" do
    it "round-trips and detects tampering" do
      key = "\x07" * 32
      iv = "\x09" * 12
      ct = described_class.aes_gcm_encrypt(key, iv, "aad", "secret")
      expect(ct.bytesize).to eq(6 + 16)
      expect(described_class.aes_gcm_decrypt(key, iv, "aad", ct)).to eq("secret")
      expect { described_class.aes_gcm_decrypt(key, iv, "xad", ct) }.to raise_error(SQRL::CryptoError)
      bad = ct.dup
      bad.setbyte(0, bad.getbyte(0) ^ 1)
      expect { described_class.aes_gcm_decrypt(key, iv, "aad", bad) }.to raise_error(SQRL::CryptoError)
      expect { described_class.aes_gcm_decrypt(key, iv, "aad", "short") }.to raise_error(SQRL::CryptoError)
    end
  end

  describe "Ed25519" do
    it "signs and verifies" do
      seed = "\x03" * 32
      pk = described_class.ed25519_public(seed)
      sig = described_class.ed25519_sign(seed, "msg")
      expect(pk.bytesize).to eq(32)
      expect(sig.bytesize).to eq(64)
      expect(described_class.ed25519_verify(pk, "msg", sig)).to be(true)
      expect(described_class.ed25519_verify(pk, "msh", sig)).to be(false)
      expect(described_class.ed25519_verify(pk, "msg", sig[0, 63])).to be(false)
      expect(described_class.ed25519_verify("x" * 31, "msg", sig)).to be(false)
    end

    it "matches RFC 8032 test 1" do
      seed = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
      expect(hex(described_class.ed25519_public(seed))).to eq("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
      expect(hex(described_class.ed25519_sign(seed, "")))
        .to eq("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    end

    it "rejects bad seed sizes" do
      expect { described_class.ed25519_public("short") }.to raise_error(SQRL::CryptoError)
    end
  end

  describe "DER-built keys (openssl gems without the raw-key API)" do
    before { skip "the openssl gem has no raw-key API to compare against" unless described_class::RAW_KEY_API }

    it "matches the keys built through OpenSSL::PKey.new_raw_private_key / new_raw_public_key" do
      prefixes = described_class.const_get(:DER_PREFIXES)
      %w[ED25519 X25519].each do |type|
        secret = OpenSSL::Random.random_bytes(32)
        via_raw = OpenSSL::PKey.new_raw_private_key(type, secret)
        via_der = OpenSSL::PKey.read(prefixes.fetch(type)[:private] + secret)
        expect(via_der.private_to_der).to eq(via_raw.private_to_der)
        expect(via_der.public_to_der[-32, 32]).to eq(via_raw.raw_public_key)
        expect(OpenSSL::PKey.read(prefixes.fetch(type)[:public] + via_raw.raw_public_key).public_to_der)
          .to eq(via_raw.public_to_der)
      end
    end
  end

  describe "X25519" do
    it "agrees both ways and matches the RFC 7748 base-point vector" do
      a = "\x01" * 32
      b = "\x02" * 32
      expect(described_class.x25519(a, described_class.x25519_base(b)))
        .to eq(described_class.x25519(b, described_class.x25519_base(a)))
      alice = unhex(SQRL::TestVectors::X25519_ALICE_PRIVATE)
      expect(hex(described_class.x25519_base(alice))).to eq(SQRL::TestVectors::X25519_ALICE_PUBLIC)
    end
  end
end
