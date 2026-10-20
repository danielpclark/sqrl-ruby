# frozen_string_literal: true

module SQRL
  # Key derivations that flow from the Identity Unlock Key, and the unlocked in-memory
  # identity.
  #
  # * IUK - Identity Unlock Key: the 256-bit root secret, only available after the user
  #   enters the rescue code. Needed to enable/remove an account and to re-key.
  # * IMK - Identity Master Key = EnHash(IUK). Derives every per-site key.
  # * ILK - Identity Lock Key = X25519(IUK, basepoint). Given to sites via SUK/VUK.
  # * Per-site seed = HMAC-SHA256(key = IMK, msg = site key string); the Ed25519 key pair
  #   from that seed is the site identity (idk / ids).
  # * INK = EnHash(per-site seed); ins = HMAC-SHA256(INK, sin).
  # * RLK/SUK/VUK - per-account identity lock values, see Identity.make_server_lock.
  # * URSK - Unlock Request Signing Key = Ed25519 seed X25519(IUK, SUK).
  module Identity
    # The identity-lock values a client sends to a server when creating or re-keying an
    # account.
    ServerLock = Struct.new(:suk, :vuk, keyword_init: true)

    module_function

    def imk_from_iuk(iuk)
      Crypto.enhash(iuk)
    end

    def ilk_from_iuk(iuk)
      Crypto.x25519_base(iuk)
    end

    def site_seed(imk, site_key)
      Crypto.hmac_sha256(imk, site_key)
    end

    # Indexed-secret response: ins = HMAC-SHA256(key = EnHash(site seed), msg = sin).
    def indexed_secret(site_seed, sin)
      Crypto.hmac_sha256(Crypto.enhash(site_seed), sin)
    end

    # Generate SUK/VUK for an Identity Lock Key using a fresh Random Lock Key.
    def make_server_lock(ilk, rlk = Util.random_bytes(32))
      suk = Crypto.x25519_base(rlk)
      dhk = Crypto.x25519(rlk, ilk)
      vuk = Crypto.ed25519_public(dhk)
      Util.wipe(dhk)
      ServerLock.new(suk: suk, vuk: vuk)
    end

    # Unlock Request Signing Key seed: X25519(IUK, SUK). Its Ed25519 public key equals the
    # VUK the server stored, which lets the server verify a +urs+ signature.
    def unlock_request_seed(iuk, suk)
      Crypto.x25519(iuk, suk)
    end
  end

  # A decrypted identity held in memory. +previous_iuks+ are ordered most-recent first.
  class UnlockedIdentity
    attr_reader :imk, :ilk, :previous_iuks

    def initialize(imk, ilk, previous_iuks = [])
      raise ArgumentError, "imk must be 32 bytes" unless imk.bytesize == 32
      raise ArgumentError, "ilk must be 32 bytes" unless ilk.bytesize == 32

      @imk = imk.b.freeze
      @ilk = ilk.b.freeze
      @previous_iuks = previous_iuks.map { |k| k.b.freeze }.freeze
    end

    # Build a brand-new identity from an Identity Unlock Key.
    def self.from_iuk(iuk, previous_iuks = [])
      new(Identity.imk_from_iuk(iuk), Identity.ilk_from_iuk(iuk), previous_iuks)
    end

    def site_seed(site_key)
      Identity.site_seed(@imk, site_key)
    end

    # Per-site Ed25519 public key (idk) for the current identity.
    def site_public_key(site_key)
      Crypto.ed25519_public(site_seed(site_key))
    end

    def previous_count
      @previous_iuks.length
    end

    # Per-site Ed25519 seed for previous identity +index+ (0 = most recent), or nil.
    def previous_site_seed(index, site_key)
      iuk = @previous_iuks[index]
      return nil unless iuk

      Identity.site_seed(Identity.imk_from_iuk(iuk), site_key)
    end

    # Per-site public key (pidk) for previous identity +index+, or nil.
    def previous_site_public_key(index, site_key)
      seed = previous_site_seed(index, site_key)
      seed && Crypto.ed25519_public(seed)
    end

    # Generate the SUK/VUK pair for a new account association on a server.
    def make_lock
      Identity.make_server_lock(@ilk)
    end

    # Unlock request signing seed using a previous identity's IUK (re-keying an account
    # still associated with that previous identity).
    def previous_unlock_request_seed(index, suk)
      iuk = @previous_iuks[index]
      iuk && Identity.unlock_request_seed(iuk, suk)
    end

    # Whether +iuk+ is the IUK this identity was derived from.
    def matches_iuk?(iuk)
      Util.secure_compare(Identity.imk_from_iuk(iuk), @imk)
    end

    # 16 hex characters identifying the identity without revealing key material.
    def fingerprint
      Util.hex_encode(Crypto.sha256("sqrl-fingerprint" + @imk))[0, 16]
    end

    def inspect
      "#<SQRL::UnlockedIdentity fingerprint=#{fingerprint} previous=#{previous_count}>"
    end
    alias to_s inspect
  end
end
