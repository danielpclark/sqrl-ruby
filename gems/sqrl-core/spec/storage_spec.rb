# frozen_string_literal: true

require "sqrl/test_vectors"

RSpec.describe SQRL::Storage do
  let(:identity_bytes) { SQRL::Util.hex_decode(SQRL::TestVectors::ANDROID_IDENTITY_HEX) }
  let(:test_identity) { SQRL::S4Identity.parse(identity_bytes) }

  # Each call advances one second, so a 1-second EnScrypt finishes after one iteration.
  def fake_clock
    t = 0
    -> { t += 1000 }
  end

  def fast_settings
    SQRL::Storage::IdentitySettings.new(pw_verify_seconds: 1)
  end

  it "parses and round-trips the reference identity in binary and text form" do
    id = test_identity
    t1 = id.type1
    expect(t1.iterations).to eq(197)
    expect(t1.settings.log_n).to eq(9)
    expect(t1.settings.option_flags).to eq(0x01f3)
    expect(t1.settings.hint_length).to eq(4)
    expect(t1.settings.pw_verify_seconds).to eq(5)
    expect(t1.settings.idle_timeout_minutes).to eq(15)
    expect(id.type2.iterations).to eq(207)
    expect(id.type3).to be_nil
    expect(id.to_bytes).to eq(identity_bytes)
    text = id.to_text
    expect(text).to start_with("SQRLDATA")
    expect(SQRL::S4Identity.parse(text)).to eq(id)
    expect(SQRL::S4Identity.parse("  #{text}\n")).to eq(id)
  end

  it "unlocks the reference identity with the password and the rescue code", :slow do
    id = test_identity
    unlocked = id.unlock(SQRL::TestVectors::ANDROID_PASSWORD)
    expect(unlocked.previous_count).to eq(0)
    expect { id.unlock_with_key("\x00" * 32) }.to raise_error(SQRL::CryptoError, /incorrect password/)
    iuk = id.unlock_iuk(SQRL::TestVectors::ANDROID_RESCUE_CODE)
    expect(SQRL::Crypto.enhash(iuk)).to eq(unlocked.imk)
    expect(SQRL::Identity.ilk_from_iuk(iuk)).to eq(unlocked.ilk)
    expect(unlocked.matches_iuk?(iuk)).to be(true)
  end

  it "rejects malformed rescue codes before doing any work" do
    expect { test_identity.unlock_iuk("1234") }.to raise_error(SQRL::FormatError)
    expect { test_identity.unlock_iuk("1234-5678-9012-3456-7890-12x4") }.to raise_error(SQRL::FormatError)
  end

  it "creates, changes the password and re-keys an identity" do
    iuk = "\x0B" * 32
    settings = fast_settings
    rescue_code = "1234-5678-9012-3456-7890-1234"
    stages = []
    id = SQRL::S4Identity.create(iuk, "hunter2", rescue_code, settings, 1, now_ms: fake_clock) { |s, _, _| stages << s }
    expect(stages.uniq).to contain_exactly("password", "rescue")
    expect(id.type1.iterations).to eq(1)
    unlocked = id.unlock("hunter2")
    expect(unlocked.imk).to eq(SQRL::Identity.imk_from_iuk(iuk))
    expect(id.unlock_iuk(rescue_code)).to eq(iuk)
    expect { id.unlock("wrong") }.to raise_error(SQRL::CryptoError, /incorrect password/)
    expect { id.unlock_iuk("0000-0000-0000-0000-0000-0000") }.to raise_error(SQRL::CryptoError, /incorrect rescue code/)

    # change password
    id.set_password(unlocked, "correct horse", settings, now_ms: fake_clock)
    expect { id.unlock("hunter2") }.to raise_error(SQRL::CryptoError)
    unlocked2 = id.unlock("correct horse")
    expect(unlocked2.imk).to eq(unlocked.imk)
    expect(id.edition).to eq(0)

    # rekey
    new_iuk = "\x0C" * 32
    new_rescue = "0000-1111-2222-3333-4444-5555"
    rekeyed = id.rekey(unlocked2, iuk, new_iuk, "pw3", new_rescue, settings, 1, now_ms: fake_clock)
    expect(rekeyed.previous_iuks).to eq([iuk])
    reloaded = SQRL::S4Identity.parse(id.to_bytes)
    unlocked3 = reloaded.unlock("pw3")
    expect(unlocked3.imk).to eq(SQRL::Identity.imk_from_iuk(new_iuk))
    expect(unlocked3.previous_iuks).to eq([iuk])
    expect(reloaded.unlock_iuk(new_rescue)).to eq(new_iuk)
    expect(reloaded.type3.length).to eq(54)
    expect(reloaded.edition).to eq(1)

    # rekey three more times: only four previous keys are kept
    cur_iuk = new_iuk
    cur_unlocked = unlocked3
    (20..23).each do |i|
      nxt = i.chr * 32
      cur_unlocked = id.rekey(cur_unlocked, cur_iuk, nxt, "pw", new_rescue, settings, 1, now_ms: fake_clock)
      cur_iuk = nxt
    end
    expect(cur_unlocked.previous_iuks.length).to eq(4)
    expect(cur_unlocked.previous_iuks[0]).to eq(22.chr * 32)
    expect(cur_unlocked.previous_iuks[3]).to eq(new_iuk)
    reloaded = SQRL::S4Identity.parse(id.to_bytes)
    expect(reloaded.type3.length).to eq(150)
    expect(reloaded.unlock("pw").previous_iuks).to eq(cur_unlocked.previous_iuks)
    # five re-keyings in total: the edition keeps counting past the four stored keys
    expect(reloaded.edition).to eq(5)
  end

  it "exports a rescue-only copy and rebuilds a password block from it" do
    iuk = "\x0D" * 32
    settings = fast_settings
    id = SQRL::S4Identity.create(iuk, "pw", "1234-5678-9012-3456-7890-1234", settings, 1, now_ms: fake_clock)
    rescue_only = id.rescue_only
    expect(rescue_only.password_block?).to be(false)
    expect(rescue_only.rescue_block?).to be(true)
    expect(rescue_only.rescue_blocks_to_bytes).to eq(id.rescue_blocks_to_bytes)
    expect { rescue_only.unlock("pw") }.to raise_error(SQRL::FormatError, /no password block/)
    recovered = SQRL::UnlockedIdentity.from_iuk(rescue_only.unlock_iuk("1234-5678-9012-3456-7890-1234"))
    rescue_only.set_password(recovered, "new pw", settings, now_ms: fake_clock)
    expect(rescue_only.unlock("new pw").imk).to eq(recovered.imk)
  end

  it "rejects duplicate blocks" do
    bytes = test_identity.to_bytes + test_identity.type2.to_bytes
    expect { SQRL::S4Identity.parse(bytes) }.to raise_error(SQRL::FormatError, /more than one type 2/)
  end

  it "NFKC-normalises passwords" do
    expect(described_class.normalize_password("ﬁsh Å")).to eq("fish Å".b)
    id = SQRL::S4Identity.create("\x03" * 32, "ﬁsh", "1234-5678-9012-3456-7890-1234", fast_settings, 1,
                                 now_ms: fake_clock)
    expect { id.unlock("fish") }.not_to raise_error
  end

  it "preserves unknown blocks" do
    bytes = test_identity.to_bytes + [9, 0, 7, 0, 1, 2, 3, 4, 5].pack("C*")
    parsed = SQRL::S4Identity.parse(bytes)
    expect(parsed.unknown.length).to eq(1)
    expect(parsed.to_bytes).to eq(bytes)
  end

  it "rejects malformed files" do
    expect { SQRL::S4Identity.parse("short") }.to raise_error(SQRL::FormatError, /too short/)
    expect { SQRL::S4Identity.parse("notaheader#{"x" * 20}") }.to raise_error(SQRL::FormatError, /header/)
    expect do
      SQRL::S4Identity.parse("sqrldata#{[200, 0, 1, 0].pack("C*")}")
    end.to raise_error(SQRL::FormatError, /claims 200 bytes/)
    expect { SQRL::S4Identity.parse_blocks([9, 0, 7, 0, 1, 2, 3, 4, 5].pack("C*")) }
      .to raise_error(SQRL::FormatError, /neither a password nor a rescue block/)
    expect { SQRL::S4Identity.parse("#{test_identity.to_bytes}\x01") }.to raise_error(SQRL::FormatError, /trailing/)
    expect(SQRL::S4Identity.parse("#{test_identity.to_bytes}\0\0\0\0\0")).to eq(test_identity)
    expect do
      SQRL::S4Identity.parse_blocks([0, 0, 1, 0, 9].pack("C*"))
    end.to raise_error(SQRL::FormatError, /zero-length/)
  end

  it "validates block sizes" do
    expect { SQRL::Storage::Type1Block.parse("x" * 10) }.to raise_error(SQRL::FormatError, /type 1 block must be 125/)
    expect { SQRL::Storage::Type2Block.parse("x" * 10) }.to raise_error(SQRL::FormatError, /type 2 block must be 73/)
    expect { SQRL::Storage::Type3Block.parse("x" * 10) }.to raise_error(SQRL::FormatError, /too short/)
    bad_edition = [54, 0, 3, 0, 0, 0].pack("C*") + ("\0" * 48)
    expect { SQRL::Storage::Type3Block.parse(bad_edition) }.to raise_error(SQRL::FormatError, /edition 0/)
    bad_len = [70, 0, 3, 0, 1, 0].pack("C*") + ("\0" * 64)
    expect { SQRL::Storage::Type3Block.parse(bad_len) }.to raise_error(SQRL::FormatError, /not 54, 86, 118 or 150/)
  end

  it "encrypts type 3 blocks only when there are previous keys" do
    imk = "\x01" * 32
    expect(SQRL::Storage::Type3Block.encrypt([], imk, 1)).to be_nil
    block = SQRL::Storage::Type3Block.encrypt(["\x02" * 32, "\x03" * 32], imk, 0)
    expect(block.edition).to eq(1)
    expect(block.length).to eq(86)
    expect(block.decrypt(imk)).to eq(["\x02" * 32, "\x03" * 32])
    expect { block.decrypt("\x09" * 32) }.to raise_error(SQRL::CryptoError, /does not verify/)
    expect(SQRL::Storage::Type3Block.parse(block.to_bytes)).to eq(block)
  end

  it "round-trips type 1 and type 2 blocks with pre-derived keys" do
    key = "\x05" * 32
    t1 = SQRL::Storage::Type1Block.encrypt_with_key("\x01" * 32, "\x02" * 32, key, "\x03" * 16, "\x04" * 12, 7, SQRL::Storage::IdentitySettings.new)
    expect(t1.to_bytes.bytesize).to eq(125)
    expect(SQRL::Storage::Type1Block.parse(t1.to_bytes)).to eq(t1)
    expect(t1.decrypt_with_key(key)).to eq(["\x01" * 32, "\x02" * 32])
    t2 = SQRL::Storage::Type2Block.encrypt_with_key("\x06" * 32, key, "\x03" * 16, 9, 7)
    expect(t2.to_bytes.bytesize).to eq(73)
    expect(SQRL::Storage::Type2Block.parse(t2.to_bytes)).to eq(t2)
  end

  describe "rescue codes" do
    it "generates 24 digits by long division" do
      code = described_class.generate_rescue_code
      expect(code).to match(/\A\d{24}\z/)
      expect(described_class.rescue_code_from_entropy("\0" * 32)).to eq("000000000000000000000000")
      # 2^256 mod 10^24, with digits least-significant first.
      e = "#{"\0" * 31}\x01"
      expect(described_class.rescue_code_from_entropy(e)).to eq("100000000000000000000000")
      e = "#{"\0" * 31}\x0A"
      expect(described_class.rescue_code_from_entropy(e)).to eq("010000000000000000000000")
    end

    it "formats and normalises" do
      expect(described_class.format_rescue_code("123456789012345678901234")).to eq("1234-5678-9012-3456-7890-1234")
      expect(described_class.normalize_rescue_code(" 1234-5678 9012-3456-7890-1234 ")).to eq("123456789012345678901234")
      expect { described_class.normalize_rescue_code("1234-5678-9012-3456-7890-12x4") }.to raise_error(SQRL::FormatError)
      expect { described_class.normalize_rescue_code("1234") }.to raise_error(SQRL::FormatError)
    end
  end

  it "has the documented default settings" do
    s = SQRL::Storage::IdentitySettings.new
    expect(s.option_flags).to eq(0x01F3)
    expect(s.hint_length).to eq(4)
    expect(s.pw_verify_seconds).to eq(5)
    expect(s.idle_timeout_minutes).to eq(15)
    expect(s.log_n).to eq(9)
    expect(SQRL::S4Identity.new.settings).to eq(s)
  end
  describe "binary files whose last byte is whitespace" do
    it "parses them without truncating the final block" do
      type2 = SQRL::Storage::Type2Block.new(salt: SQRL::Util.random_bytes(16), log_n: 9, iterations: 1,
                                            enc_iuk: SQRL::Util.random_bytes(32), tag: "#{"\x00" * 15}\n")
      bytes = SQRL::Storage::HEADER_BINARY + type2.to_bytes
      expect(bytes.byteslice(-1)).to eq("\n")
      parsed = SQRL::S4Identity.parse(bytes)
      expect(parsed.to_bytes).to eq(bytes)
      expect(SQRL::S4Identity.parse("\r\n#{bytes}").to_bytes).to eq(bytes)
    end

    it "still tolerates whitespace around the SQRLDATA text form" do
      type2 = SQRL::Storage::Type2Block.new(salt: SQRL::Util.random_bytes(16), log_n: 9, iterations: 1,
                                            enc_iuk: SQRL::Util.random_bytes(32), tag: SQRL::Util.random_bytes(16))
      text = SQRL::Storage::HEADER_TEXT + SQRL::Util.b64u_encode(type2.to_bytes)
      expect(SQRL::S4Identity.parse("  #{text}\n\n").to_bytes).to eq(SQRL::Storage::HEADER_BINARY + type2.to_bytes)
    end
  end
end
