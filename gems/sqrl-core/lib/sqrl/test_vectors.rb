# frozen_string_literal: true

module SQRL
  # Test vectors published by GRC and by the SQRL developer community, shared by every
  # gem's test-suite.
  #
  # Sources:
  # * "SQRL Cryptography" v1.04 (December 2019), "SQRL Cryptography Test Vectors": the
  #   Spec-Vectors-Identity (password, rescue code, textual identity) and the client-side
  #   SQRL-PASS.log / SQRL.log excerpts.
  # * https://www.grc.com/sqrl/storage.htm: the official EnScrypt vectors.
  # * grc.sqrl.dev newsgroup, "SQRL Identity encryption" (Adam Comley, 2014): EnScrypt with
  #   a 16-byte salt, cross-validated against GRC's EnScrypt.exe.
  # * grc.sqrl newsgroup, "Base56 Examples" (Paul Holder, March 2019): base56 textual
  #   encodings validated against the GRC SQRL client's export.
  # * The open-source Android SQRL client's test code: a complete S4 identity file.
  module TestVectors
    SPEC_PASSWORD = "Zingo-Bingo-Slingo-Dingo"
    SPEC_RESCUE_CODE = "1198-8748-7132-2838-8318-7570"
    SPEC_TEXTUAL = <<~TEXT.chomp
      KKcC 3BaX akxc Xwbf xki7
      k7mF GHhg jQes gzWd 6TrK
      vMsZ dBtB pZbC zsz8 cUWj
      DtS2 ZK2s ZdAQ 8Yx3 iDyt
      QuXt CkTC y6gc qG8n Xfj9
      bHDA 422
    TEXT
    SPEC_IMK = "2E471E106D758F3C7B242C8A4A0513A7192D8EDDB917BDD019F19E38ED292BA8"
    # Per-site values for sqrl.grc.com from SQRL.log.
    SPEC_SITE = "sqrl.grc.com"
    SPEC_SITE_SEED = "7A550E0797EF9E617D0E544EBE27FDE749D9EC2472BF9618DEE4C063EEFD51B5"
    SPEC_SITE_PUBLIC_KEY = "DA3801F9C47E1279588253DD193A0EB9C29823A083EAC52A7F893D32D92E897B"
    SPEC_SITE_IDK = "2jgB-cR-EnlYglPdGToOucKYI6CD6sUqf4k9MtkuiXs"

    # SQRL.log transaction 1 and 2 (the query and ident against sqrl.grc.com).
    SPEC_URL = "sqrl://sqrl.grc.com/cli.sqrl?nut=fXkb4MBToCm7&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw"
    SPEC_CANCEL_URL = "https://sqrl.grc.com/demo"
    SPEC_QUERY_CLIENT = "ver=1\r\ncmd=query\r\nidk=#{SPEC_SITE_IDK}\r\nopt=cps~suk\r\n".freeze
    SPEC_QUERY_CLIENT_B64_PREFIX = "client=dmVyPTENCmNtZD1xdWVyeQ0KaWRrPTJqZ0ItY1ItRW5sWWdsUGRHVG9PdWNLWUk2Q0Q2c1VxZjRrOU10a3Vp"
    SPEC_QUERY_SERVER_B64_FRAGMENT = "&server=c3FybDovL3NxcmwuZ3JjLmNvbS9jbGkuc3FybD9udXQ9ZlhrYjRNQlRvQ203JmNhbj1hSFIwY0hNNkx5OXpj"
    SPEC_QUERY_IDS = "qXFikmg_jZQJ7GjKCA_zBwzras2QyQAwWw2s80ZcUHmLLBUN5_hPuFtB6ZoV5wUcNs5XmSrqg1FQwGA6RlVBAQ"
    SPEC_REPLY1 = "ver=1\r\nnut=1WM9lfF1ST-z\r\ntif=5\r\nqry=/cli.sqrl?nut=1WM9lfF1ST-z\r\n" \
                  "suk=BMFDm7bPlsQojuJsoDTvlS1McnwgScvktF84vLjscGk\r\n"
    SPEC_REPLY1_B64_PREFIX = "dmVyPTENCm51dD0xV005bGZGMVNULXoNCnRpZj01DQpxcnk9L2NsaS5zcXJsP251dD0xV005bGZGMVNULXoN"
    SPEC_REPLY1_SUK = "BMFDm7bPlsQojuJsoDTvlS1McnwgScvktF84vLjscGk"
    SPEC_IDENT_URL = "https://sqrl.grc.com/cli.sqrl?nut=1WM9lfF1ST-z"
    SPEC_IDENT_CLIENT = "ver=1\r\ncmd=ident\r\nidk=#{SPEC_SITE_IDK}\r\nopt=cps~suk\r\n".freeze
    SPEC_IDENT_CLIENT_B64_PREFIX = "client=dmVyPTENCmNtZD1pZGVudA0KaWRrPTJqZ0ItY1ItRW5sWWdsUGRHVG9PdWNLWUk2Q0Q2c1VxZjRrOU10a3Vp"
    SPEC_IDENT_IDS = "kQI05IpE_cu4u0mf7jymbap09hmS6ZCWjBGKUYnSNVRTXPbreTvDWHKNbSkUlQT2bx3wXwW3cCLBD0Qedd64AA"
    SPEC_REPLY2 = "ver=1\r\nnut=BEFAI1tJYfBm\r\ntif=5\r\nqry=/cli.sqrl?nut=BEFAI1tJYfBm\r\n" \
                  "suk=BMFDm7bPlsQojuJsoDTvlS1McnwgScvktF84vLjscGk\r\n" \
                  "url=https://sqrl.grc.com/auth.test?4hVTe9LGHhMTuxz_mm6vRc_q\r\n"
    SPEC_CPS_URL = "https://sqrl.grc.com/auth.test?4hVTe9LGHhMTuxz_mm6vRc_q"

    # EnScrypt vectors: [password, salt hex, iterations, expected hex].
    ENSCRYPT = [
      # Official vectors from https://www.grc.com/sqrl/storage.htm
      ["", "", 1, "a8ea62a6e1bfd20e4275011595307aa302645c1801600ef5cd79bf9d884d911c"],
      ["", "", 100, "45a42a01709a0012a37b7b6874cf16623543409d19e7740ed96741d2e99aab67"],
      ["password", "", 123, "129d96d1e735618517259416a605be7094c2856a53c14ef7d4e4ba8e4ea36aeb"],
      ["password", "0000000000000000000000000000000000000000000000000000000000000000", 123,
       "2f30b9d4e5c48056177ff90a6cc9da04b648a7e8451dfa60da56c148187f6a7d"],
      # SQRL-PASS.log: password DeScryption, 179 iterations
      [SPEC_PASSWORD, "F5019F96E9F64D32BEAE43145ACEF2CF", 179,
       "bc151224fc6b72152021edbe3ade523f98be99c491334bba9fd8b587eb51e36d"],
      # SQRL-PASS.log: QuickPass hint "Zing", 31 iterations
      ["Zing", "CD2E1EA56DE20FE036B6D2FA867DF50A", 31,
       "ddc7f5d12caa26a869488ad83df8ed480072076dfd94eee5f6f1bd0dde02b9d9"],
      # grc.sqrl.dev newsgroup, 16- and 32-byte salts
      ["Sqrl123Test", "0123456789abcdef0123456789abcdef", 63,
       "83961678d0e808f29b5dcc045236ad7fd249d7dfd7284b461976b1f1b8a45df0"],
      ["Sqrl123Test", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 63,
       "da06576fbe58fb20bd8c4f1204a87aa8fad21078473dd770bb7ee7faff8a2f4a"]
    ].map(&:freeze).freeze

    # Base56 vectors validated against GRC's client: {hex input => raw encoding}.
    BASE56_SHORT = {
      "00" => "22Y", "01" => "32B", "0F" => "H2M", "55" => "X3v", "C5" => "X57", "FE" => "Y6e", "FF" => "Z6V",
      "0000" => "222B", "0101" => "b628", "0F0F" => "rE3N", "1010" => "SK3T", "7F7F" => "rQCj",
      "8080" => "SVC5", "FEFE" => "gpN7", "FFFF" => "HuNh",
      "000000" => "22222z", "010101" => "tyN22r", "7F7F7F" => "9Tar2S", "808080" => "2Sxr2D",
      "FEFEFE" => "GuAh3n", "FFFFFF" => "9tXh3W",
      "0102030405060708090A0B0C0D0E0F10" => "tG5vDbjTXT2zfJ5cMfvg3A62d"
    }.freeze
    BASE56_80_HEX = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627" \
                    "28292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F50"
    BASE56_80_TEXT = <<~TEXT.chomp
      b6w8 RYMv S427 Gtt5 sXBj
      UB5n vHZH PbHr uAM9 MgUR
      fzT8 qs8f EEEp kUPV GH6R
      ac4u Zdrk CwLJ Wxmy 8upX
      rU9N Bn6P qcY9 HXKt ybEC
      Sdh9 R22r SjAd 48i2 Y
    TEXT
    BASE56_87_HEX = "18A2D975F61A3B6F1975FA2A9E3FBA2C7BE73732A0E34F006328E4BD938CFB6E292A50845C5A6B83F769" \
                    "7EAC8A49BF97221C2F06C1F4B251BDB865AF1E1E28E62D635959BEF7927CD658A7C2CA1AD5570DC6C066BA6EAF"
    BASE56_87_TEXT = <<~TEXT.chomp
      sMrK xrbJ dHz5 s3mu EGWw
      RjWM UbAV MMsq SwMM R7C6
      theF MsSg PDJ4 BHVb jLau
      KpW8 cbsU mTpd eueZ ZYMU
      HgcB kffR Nviu pxb9 UvxN
      fN54 3id9 CdRe L254 ZzEb
      4LBd pNL
    TEXT
    # Sample textual identity (a single type 2 block) from the Android client's test harness.
    ANDROID_TEXTUAL = "KB3Z 8My9 CVUX C34K B8NM bEXm jcUK RAq6 JT9p DaYW UstG K9hH xX98 KxHU weVa RvpV " \
                      "wJd5 JXbf eEDf 4cYy hzNL j6dW Ehq3 KXCV YSBf nRJd rAN"

    # A real identity file (from the open-source Android SQRL client's test code) with the
    # password +Testing1234+ and rescue code +7276-0587-2230-1119-8559-3839+.
    ANDROID_IDENTITY_HEX = "7371726c646174617d0001002d00b51fd99559b887d106a8d877c70133bb20a12fa1a7c829b194db94f309c5" \
                           "000000f30104050f000d174cc6e7b70baa158aa4ce75e2f2b99a02a40e4beb2e5d16c2f03442bd3e932035" \
                           "419a63885a663125a600e5486c42b38f708c1094ced1ab0b0050137f6df449caf78581fec678408a804caf74" \
                           "f91c490002005528fc85e3e36866a85574146fe7776d09cf0000004a4e12277dd48366fc1f335dd37188bbcb" \
                           "a02bc32a12aef0188f5e83593665518483d638b80051c2b4b013491eb06835"
    ANDROID_PASSWORD = "Testing1234"
    ANDROID_RESCUE_CODE = "7276-0587-2230-1119-8559-3839"

    # RFC 7748 X25519 base-point vector.
    X25519_ALICE_PRIVATE = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    X25519_ALICE_PUBLIC = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
  end
end
