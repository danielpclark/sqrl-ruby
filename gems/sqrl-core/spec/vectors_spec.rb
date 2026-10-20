# frozen_string_literal: true

require "sqrl/test_vectors"

# Published test vectors that do not need the wire protocol (those live in
# protocol_vectors_spec.rb).
RSpec.describe "SQRL test vectors" do
  V = SQRL::TestVectors

  it "decodes the Spec-Vectors-Identity textual identity and re-encodes it exactly" do
    cleaned = V::SPEC_TEXTUAL.delete(" \n")
    expect(cleaned.length).to eq(107) # 101 data chars + 6 check chars
    bytes = SQRL::Textual.decode(V::SPEC_TEXTUAL)
    expect(bytes.bytesize).to eq(73)
    id = SQRL::S4Identity.parse_blocks(bytes)
    expect(id.type1).to be_nil
    expect(id.type2).not_to be_nil
    expect(id.type3).to be_nil
    expect(SQRL::Textual.format_for_display(SQRL::Textual.encode(bytes))).to eq(V::SPEC_TEXTUAL)
  end

  it "derives the IMK and the sqrl.grc.com site key from the rescue code", :slow do
    id = SQRL::S4Identity.parse_blocks(SQRL::Textual.decode(V::SPEC_TEXTUAL))
    iuk = id.unlock_iuk(V::SPEC_RESCUE_CODE)
    imk = SQRL::Crypto.enhash(iuk)
    expect(SQRL::Util.hex_encode(imk).upcase).to eq(V::SPEC_IMK)

    seed = SQRL::Crypto.hmac_sha256(imk, V::SPEC_SITE)
    expect(SQRL::Util.hex_encode(seed).upcase).to eq(V::SPEC_SITE_SEED)
    pk = SQRL::Crypto.ed25519_public(seed)
    expect(SQRL::Util.hex_encode(pk).upcase).to eq(V::SPEC_SITE_PUBLIC_KEY)
    expect(SQRL::Util.b64u_encode(pk)).to eq(V::SPEC_SITE_IDK)

    unlocked = SQRL::UnlockedIdentity.from_iuk(iuk)
    expect(SQRL::Util.b64u_encode(unlocked.site_public_key(V::SPEC_SITE))).to eq(V::SPEC_SITE_IDK)
  end

  it "derives the site key from the published IMK without the rescue code" do
    imk = SQRL::Util.hex_decode(V::SPEC_IMK)
    identity = SQRL::UnlockedIdentity.new(imk, "\0" * 32)
    expect(SQRL::Util.b64u_encode(identity.site_public_key(V::SPEC_SITE))).to eq(V::SPEC_SITE_IDK)
  end
end
