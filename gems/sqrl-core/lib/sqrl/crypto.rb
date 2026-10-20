# frozen_string_literal: true

require "openssl"

module SQRL
  # Cryptographic primitives used by SQRL.
  #
  # * EnHash: 16 chained iterations of SHA-256 whose outputs are XORed together.
  # * EnScrypt: scrypt (N = 2**log_n, r = 256, p = 1, dkLen = 32) chained and XORed over
  #   many iterations, either for a fixed iteration count or for a fixed duration.
  # * HMAC-SHA256, AES-256-GCM, Ed25519 and X25519 via OpenSSL.
  #
  # All byte arguments and results are binary-encoded Strings.
  module Crypto
    # scrypt +r+ parameter mandated by SQRL.
    SCRYPT_R = 256
    # scrypt +p+ parameter mandated by SQRL.
    SCRYPT_P = 1
    # Default scrypt log2(N) used by SQRL clients (N = 512).
    DEFAULT_LOG_N = 9

    # Whether the openssl gem has OpenSSL::PKey.new_raw_private_key / new_raw_public_key
    # (openssl 3.2, bundled with Ruby 3.3). Older supported versions (openssl 3.0 and 3.1,
    # bundled with Ruby 3.1 and 3.2) build the same keys from their DER encodings instead.
    RAW_KEY_API = OpenSSL::PKey.respond_to?(:new_raw_private_key) && OpenSSL::PKey.respond_to?(:new_raw_public_key)

    # DER prefixes that turn a 32-byte Ed25519 / X25519 key into a PKCS#8 PrivateKeyInfo or
    # a SubjectPublicKeyInfo (RFC 8410): the key bytes follow the prefix verbatim.
    DER_PREFIXES = {
      "ED25519" => {
        private: ["302e020100300506032b657004220420"].pack("H*"),
        public: ["302a300506032b6570032100"].pack("H*")
      },
      "X25519" => {
        private: ["302e020100300506032b656e04220420"].pack("H*"),
        public: ["302a300506032b656e032100"].pack("H*")
      }
    }.freeze
    private_constant :DER_PREFIXES

    module_function

    # SHA-256 digest.
    # @param data [String] bytes
    # @return [String] 32 binary bytes
    def sha256(data)
      OpenSSL::Digest.new("SHA256").digest(data)
    end

    # HMAC-SHA256.
    # @param key [String] key bytes
    # @param data [String] message bytes
    # @return [String] 32 binary bytes
    def hmac_sha256(key, data)
      OpenSSL::HMAC.digest("SHA256", key, data)
    end

    # EnHash: SHA-256 applied 16 times in a chain; all 16 outputs XORed together.
    def enhash(input)
      current = sha256(input)
      acc = current.bytes
      15.times do
        current = sha256(current)
        current.each_byte.with_index { |b, i| acc[i] ^= b }
      end
      acc.pack("C*")
    end

    # One raw scrypt invocation with SQRL's parameters (r = 256, p = 1, dkLen = 32).
    def scrypt_once(password, salt, log_n = DEFAULT_LOG_N)
      OpenSSL::KDF.scrypt(password.b, salt: salt.b, N: 1 << log_n, r: SCRYPT_R, p: SCRYPT_P, length: 32)
    rescue OpenSSL::KDF::KDFError => e
      raise CryptoError, "scrypt unavailable or failed (FIPS mode?): #{e.message}"
    end

    # EnScrypt with a fixed iteration count.
    #
    # The first iteration uses the caller-supplied salt; each subsequent iteration uses the
    # previous iteration's output as its salt, and the result is the XOR of every
    # iteration's output. The block, if given, is called after each iteration with the
    # number of iterations completed.
    def enscrypt_iterations(password, salt, log_n, iterations)
      iterations = [iterations.to_i, 1].max
      key = scrypt_once(password, salt, log_n)
      acc = key.bytes
      yield 1 if block_given?
      (1...iterations).each do |i|
        key = scrypt_once(password, key, log_n)
        key.each_byte.with_index { |b, j| acc[j] ^= b }
        yield i + 1 if block_given?
      end
      acc.pack("C*")
    end

    # EnScrypt for (at least) +duration_ms+ milliseconds. +now_ms+ is a callable returning
    # a monotonic millisecond clock (injectable for tests). Returns +[key, iterations]+;
    # the iteration count must be stored so the key can be re-derived with
    # enscrypt_iterations. The block, if given, receives +(elapsed_ms, duration_ms)+.
    def enscrypt_duration(password, salt, log_n, duration_ms, now_ms: method(:monotonic_ms))
      start = now_ms.call
      key = scrypt_once(password, salt, log_n)
      acc = key.bytes
      iterations = 1
      elapsed = [now_ms.call - start, 0].max
      yield elapsed, duration_ms if block_given?
      while elapsed < duration_ms && iterations < 0xFFFF_FFFF
        key = scrypt_once(password, key, log_n)
        key.each_byte.with_index { |b, j| acc[j] ^= b }
        iterations += 1
        elapsed = [now_ms.call - start, 0].max
        yield elapsed, duration_ms if block_given?
      end
      [acc.pack("C*"), iterations]
    end

    # @return [Integer] a monotonic clock in milliseconds (the default +now_ms+ for {enscrypt_duration})
    def monotonic_ms
      (Process.clock_gettime(Process::CLOCK_MONOTONIC) * 1000).to_i
    end

    # AES-256-GCM encryption. Returns ciphertext followed by the 16-byte tag.
    def aes_gcm_encrypt(key, iv, aad, plaintext)
      cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
      cipher.key = key
      cipher.iv = iv
      cipher.auth_data = aad
      out = cipher.update(plaintext.b) + cipher.final
      out + cipher.auth_tag(16)
    end

    # AES-256-GCM decryption of +ciphertext || tag+. Raises CryptoError when the tag does
    # not verify.
    def aes_gcm_decrypt(key, iv, aad, ciphertext_and_tag)
      raise CryptoError, "ciphertext too short" if ciphertext_and_tag.bytesize < 16

      ciphertext = ciphertext_and_tag.byteslice(0, ciphertext_and_tag.bytesize - 16)
      tag = ciphertext_and_tag.byteslice(-16, 16)
      cipher = OpenSSL::Cipher.new("aes-256-gcm").decrypt
      cipher.key = key
      cipher.iv = iv
      cipher.auth_tag = tag
      cipher.auth_data = aad
      cipher.update(ciphertext) + cipher.final
    rescue OpenSSL::Cipher::CipherError
      raise CryptoError, "authentication tag mismatch"
    end

    # Ed25519 signing key object from a 32-byte seed.
    def ed25519_from_seed(seed)
      raise CryptoError, "ed25519 seed must be 32 bytes" unless seed.bytesize == 32

      raw_private_key("ED25519", seed.b)
    end

    # Public key bytes of the Ed25519 key derived from +seed+.
    def ed25519_public(seed)
      raw_public_bytes(ed25519_from_seed(seed))
    end

    # Sign +msg+ with the Ed25519 key derived from +seed+; returns the 64-byte signature.
    def ed25519_sign(seed, msg)
      ed25519_from_seed(seed).sign(nil, msg.b)
    end

    # Verify an Ed25519 signature. Returns true/false; never raises on bad input.
    def ed25519_verify(public_key, msg, signature)
      return false unless public_key.bytesize == 32 && signature.bytesize == 64

      raw_public_key("ED25519", public_key.b).verify(nil, signature.b, msg.b)
    rescue OpenSSL::PKey::PKeyError
      false
    end

    # X25519 public key for a scalar (scalar multiplication of the base point).
    def x25519_base(scalar)
      raw_public_bytes(raw_private_key("X25519", scalar.b))
    end

    # X25519 Diffie-Hellman: +scalar * point+.
    def x25519(scalar, point)
      raw_private_key("X25519", scalar.b).derive(raw_public_key("X25519", point.b))
    end

    # Private key object of +type+ ("ED25519" or "X25519") from its 32 raw bytes.
    # @api private
    def raw_private_key(type, bytes)
      return OpenSSL::PKey.new_raw_private_key(type, bytes) if RAW_KEY_API

      OpenSSL::PKey.read(DER_PREFIXES.fetch(type)[:private] + bytes)
    end

    # Public key object of +type+ ("ED25519" or "X25519") from its 32 raw bytes.
    # @api private
    def raw_public_key(type, bytes)
      return OpenSSL::PKey.new_raw_public_key(type, bytes) if RAW_KEY_API

      OpenSSL::PKey.read(DER_PREFIXES.fetch(type)[:public] + bytes)
    end

    # The 32 raw public key bytes of an Ed25519 or X25519 key object.
    # @api private
    def raw_public_bytes(pkey)
      return pkey.raw_public_key if RAW_KEY_API

      # A SubjectPublicKeyInfo for these key types is the 12-byte prefix followed by the key.
      pkey.public_to_der[-32, 32]
    end
  end
end
