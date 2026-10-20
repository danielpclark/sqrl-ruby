# frozen_string_literal: true

require "tmpdir"

RSpec.describe SQRL::Client::Identity do
  let(:clock) { described_class.fast_clock }

  describe ".ephemeral" do
    it "is random without a seed and deterministic with one" do
      expect(described_class.ephemeral.fingerprint).not_to eq(described_class.ephemeral.fingerprint)
      expect(described_class.ephemeral("bot").fingerprint).to eq(described_class.ephemeral("bot").fingerprint)
      expect(described_class.ephemeral("bot").fingerprint).not_to eq(described_class.ephemeral("other").fingerprint)
      raw = "\x07" * 32
      expect(described_class.ephemeral(raw).iuk).to eq(raw.b)
      expect(described_class.ephemeral("bot")).to be_iuk
      expect(described_class.ephemeral("bot").inspect).not_to include(SQRL::Util.hex_encode(described_class.ephemeral("bot").iuk))
    end

    it "re-keys in memory, keeping up to four previous identities" do
      id = described_class.ephemeral("rekey")
      first = id.iuk
      id.rekey!
      expect(id.iuk).not_to eq(first)
      expect(id.previous_count).to eq(1)
      expect(id.unlocked.previous_iuks.first).to eq(first)
      expect(id.previous_identity.iuk).to eq(first)
      4.times { id.rekey! }
      expect(id.previous_count).to eq(4)
      expect(id.export).to match(/\A\h{64}\z/)
    end
  end

  describe ".create / .load" do
    it "creates an S4 identity file, reloads it and recovers the IUK with the rescue code" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "bot.sqrl")
        created = described_class.create(password: "hunter2", path: path, pw_seconds: 1, rescue_seconds: 0.001, now_ms: clock)
        expect(created.rescue_code).to match(/\A\d{4}(-\d{4}){5}\z/)
        expect(File.binread(path)).to start_with("sqrldata")
        expect(created).to be_iuk

        loaded = described_class.load(path, password: "hunter2")
        expect(loaded.fingerprint).to eq(created.fingerprint)
        expect(loaded).not_to be_iuk
        expect { loaded.rekey! }.to raise_error(SQRL::Client::IdentityLocked)
        expect { described_class.load(path, password: "wrong") }.to raise_error(SQRL::CryptoError)
        expect { loaded.unlock_iuk!("0000-0000-0000-0000-0000-0000") }.to raise_error(SQRL::CryptoError)
        expect(loaded.unlock_iuk!(created.rescue_code)).to eq(created.iuk)
        expect(loaded).to be_iuk

        # textual export → rescue-only import → same identity, with a new password block
        textual = SQRL::Textual.format_for_display(SQRL::Textual.encode(created.s4.rescue_blocks_to_bytes))
        imported = described_class.from_textual(textual, rescue_code: created.rescue_code, password: "new pw", now_ms: clock)
        expect(imported.fingerprint).to eq(created.fingerprint)
        expect(imported.iuk).to eq(created.iuk)
        expect(imported.s4).to be_password_block
        expect(described_class.from_s4(SQRL::S4Identity.parse(imported.export), password: "new pw").fingerprint).to eq(created.fingerprint)

        # re-key a file-backed identity
        rekeyed = loaded.rekey!(password: "hunter3", now_ms: clock, rescue_seconds: 0.001)
        expect(rekeyed.previous_count).to eq(1)
        expect(rekeyed.rescue_code).not_to eq(created.rescue_code)
        reloaded = described_class.load(path, password: "hunter3", rescue_code: rekeyed.rescue_code)
        expect(reloaded.fingerprint).to eq(rekeyed.fingerprint)
        expect(reloaded.previous_count).to eq(1)
        expect(reloaded.previous_identity.fingerprint).to eq(created.fingerprint)
      end
    end

    it "loads SQRLDATA text files too" do
      Dir.mktmpdir do |dir|
        created = described_class.create(password: "pw", pw_seconds: 1, rescue_seconds: 0.001, now_ms: clock)
        path = File.join(dir, "bot.txt")
        File.write(path, created.export)
        expect(created.export).to start_with("SQRLDATA")
        expect(described_class.load(path, password: "pw").fingerprint).to eq(created.fingerprint)
      end
    end
  end

  describe ".from_env" do
    it "builds an ephemeral identity from SQRL_IUK_HEX" do
      id = described_class.from_env({ "SQRL_IUK_HEX" => "11" * 32 })
      expect(id.iuk).to eq("\x11".b * 32)
    end

    it "loads a file with the password from a file" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "bot.sqrl")
        created = described_class.create(password: "s3cret", path: path, pw_seconds: 1, rescue_seconds: 0.001, now_ms: clock)
        pw_file = File.join(dir, "pw")
        File.write(pw_file, "s3cret\n")
        id = described_class.from_env({ "SQRL_IDENTITY_FILE" => path, "SQRL_PASSWORD_FILE" => pw_file })
        expect(id.fingerprint).to eq(created.fingerprint)
        expect { described_class.from_env({ "SQRL_IDENTITY_FILE" => path }) }.to raise_error(SQRL::Client::IdentityLocked)
      end
    end

    it "returns nil when nothing is configured" do
      expect(described_class.from_env({})).to be_nil
    end
  end
end
