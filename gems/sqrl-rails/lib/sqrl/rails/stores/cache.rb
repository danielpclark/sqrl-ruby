# frozen_string_literal: true

module SQRL
  module Rails
    # Store implementations shipped with the Rails integration.
    module Stores
      # The three {SQRL::Server} store interfaces on an +ActiveSupport::Cache::Store+, for
      # applications that keep short-lived login state in Redis or Memcached rather than
      # in the database:
      #
      #   config.sqrl.stores = :cache               # uses Rails.cache
      #   config.sqrl.cache_store = ActiveSupport::Cache::RedisCacheStore.new(url: ENV["REDIS_URL"])
      #
      # Single use is implemented as read-then-+delete+: every supported store deletes a
      # key atomically and reports whether it existed, so concurrent consumers of one nut
      # or one CPS token see exactly one winner. Nuts and pending logins expire through
      # the cache's own TTL, so +prune!+ has nothing to do.
      #
      # Identities are durable account data and are kept here too (they are what a
      # cache store makes you lose on eviction), so this set is meant for sites whose
      # cache is persistent (Redis with persistence) or that pair it with their own
      # identity store:
      #
      #   stores = SQRL::Rails::Stores::Cache.stores(Rails.cache)
      #   stores.identities = SQRL::Rails::Stores::ActiveRecord::IdentityStore.new
      #   config.sqrl.stores = stores
      #
      # +FileStore+, +MemoryStore+ and +NullStore+ cannot share state between processes
      # or delete atomically across them, so they are refused in production unless
      # +allow_unsafe: true+ is passed.
      module Cache
        # Cache store classes without an atomic delete; refused in production.
        UNSAFE_STORES = %w[ActiveSupport::Cache::FileStore ActiveSupport::Cache::MemoryStore
                           ActiveSupport::Cache::NullStore].freeze

        # @param cache [ActiveSupport::Cache::Store]
        # @param namespace [String] key prefix
        # @param identity_ttl [Integer, nil] seconds identities live (nil: never expire)
        # @param allow_unsafe [Boolean] accept process-local stores in production
        # @return [SQRL::Server::Stores]
        def self.stores(cache = ::Rails.cache, namespace: "sqrl", identity_ttl: nil, allow_unsafe: false)
          check!(cache, allow_unsafe: allow_unsafe)
          SQRL::Server::Stores.new(nuts: NutStore.new(cache, namespace: namespace),
                                   identities: IdentityStore.new(cache, namespace: namespace, ttl: identity_ttl),
                                   pending_logins: PendingLoginStore.new(cache, namespace: namespace))
        end

        def self.check!(cache, allow_unsafe: false)
          raise Error, "config.sqrl.cache_store must be an ActiveSupport::Cache::Store" unless cache.respond_to?(:read) && cache.respond_to?(:delete)
          return if allow_unsafe || !defined?(::Rails) || !::Rails.respond_to?(:env) || !::Rails.env.production?
          return unless UNSAFE_STORES.include?(cache.class.name)

          raise Error, "#{cache.class.name} is process-local and cannot back SQRL stores in production; " \
                       "use a Redis or Memcached cache store (or pass allow_unsafe: true)"
        end

        # Serialization shared by the stores: binary fields are base64url strings, times
        # are integers, so any cache serializer (Marshal, JSON, MessagePack) works.
        module Codec
          module_function

          # @return [String, nil] binary bytes as base64url
          def bin(bytes) = bytes.nil? ? nil : SQRL::Util.b64u_encode(bytes.b)
          # @return [String, nil] binary bytes from base64url
          def unbin(text) = text.nil? ? nil : SQRL::Util.b64u_decode(text)
          # @return [Integer, nil] a Time as epoch seconds
          def time(value) = value&.to_i
          # @return [Time, nil] a Time from epoch seconds
          def untime(value) = value.nil? ? nil : Time.at(value.to_i)
        end

        # Common plumbing.
        class Base
          def initialize(cache, namespace:)
            @cache = cache
            @namespace = namespace
          end

          private

          def key(*parts)
            ([@namespace] + parts).join(":")
          end

          # Seconds until +expires_at+ (at least 1), or nil.
          def ttl_until(expires_at, now)
            return nil if expires_at.nil?

            [(expires_at.to_i - now.to_i), 1].max
          end
        end

        # @see SQRL::Server::NutStore
        class NutStore < Base
          # Issue on the cache store; same contract as +SQRL::Server::NutStore#issue+.
          def issue(nut:, pending_login_id:, expected_server:, ip:, bound_idk:, expires_at:)
            record = SQRL::Server::NutRecord.new(nut: nut, pending_login_id: pending_login_id,
                                                 expected_server: expected_server, ip: ip, bound_idk: bound_idk,
                                                 expires_at: expires_at, used_at: nil)
            @cache.write(key("nut", nut), dump(record), expires_in: ttl_until(expires_at, Time.now))
            record
          end

          # Consume on the cache store; same contract as +SQRL::Server::NutStore#consume+.
          def consume(nut, now: Time.now)
            return nil if nut.nil? || nut.empty?

            data = @cache.read(key("nut", nut))
            return nil unless data
            # Deleting is the single-use guarantee: only one caller gets +true+.
            return nil unless @cache.delete(key("nut", nut))

            record = load(data)
            return nil if record.expires_at && record.expires_at <= now

            record.used_at = now
            record
          end

          # Entries expire through the cache TTL.
          def prune!(_now = Time.now)
            nil
          end

          private

          def dump(r)
            { "nut" => r.nut, "pending_login_id" => r.pending_login_id, "expected_server" => r.expected_server,
              "ip" => r.ip, "bound_idk" => Codec.bin(r.bound_idk), "expires_at" => Codec.time(r.expires_at) }
          end

          def load(h)
            SQRL::Server::NutRecord.new(nut: h["nut"], pending_login_id: h["pending_login_id"],
                                        expected_server: h["expected_server"], ip: h["ip"],
                                        bound_idk: Codec.unbin(h["bound_idk"]),
                                        expires_at: Codec.untime(h["expires_at"]), used_at: nil)
          end
        end

        # @see SQRL::Server::IdentityStore
        class IdentityStore < Base
          def initialize(cache, namespace:, ttl: nil)
            super(cache, namespace: namespace)
            @ttl = ttl
          end

          # Find on the cache store; same contract as +SQRL::Server::IdentityStore#find+.
          def find(idk)
            data = @cache.read(key("id", Codec.bin(idk)))
            data && load(data)
          end

          def create(**attrs)
            identity = SQRL::Server::Identity.new(**attrs)
            k = key("id", Codec.bin(identity.idk))
            raise ArgumentError, "identity already exists" if @cache.exist?(k)

            write(identity)
            identity
          end

          # Update on the cache store; same contract as +SQRL::Server::IdentityStore#update+.
          def update(idk, **attrs)
            identity = find(idk)
            return nil unless identity

            attrs.each { |name, value| identity[name] = value }
            write(identity)
            identity
          end

          # Rekey on the cache store; same contract as +SQRL::Server::IdentityStore#rekey+.
          def rekey(old_idk, new_idk, suk:, vuk:, ins:)
            identity = find(old_idk)
            return nil unless identity

            identity.idk = new_idk
            identity.suk = suk
            identity.vuk = vuk
            identity.ins = ins
            write(identity)
            @cache.delete(key("id", Codec.bin(old_idk)))
            @cache.write(key("superseded", Codec.bin(old_idk)), Codec.bin(new_idk), expires_in: @ttl)
            identity
          end

          def superseded?(idk)
            @cache.exist?(key("superseded", Codec.bin(idk)))
          end

          # Remove on the cache store; same contract as +SQRL::Server::IdentityStore#remove+.
          def remove(idk)
            identity = find(idk)
            return nil unless identity

            @cache.delete(key("id", Codec.bin(idk)))
            identity
          end

          private

          def write(identity)
            @cache.write(key("id", Codec.bin(identity.idk)), dump(identity), expires_in: @ttl)
          end

          def dump(i)
            { "idk" => Codec.bin(i.idk), "suk" => Codec.bin(i.suk), "vuk" => Codec.bin(i.vuk),
              "disabled" => i.disabled == true, "sqrlonly" => i.sqrlonly == true, "hardlock" => i.hardlock == true,
              "ins" => i.ins, "logins" => i.logins.to_i, "user_ref" => i.user_ref }
          end

          def load(h)
            SQRL::Server::Identity.new(idk: Codec.unbin(h["idk"]), suk: Codec.unbin(h["suk"]), vuk: Codec.unbin(h["vuk"]),
                                       disabled: h["disabled"], sqrlonly: h["sqrlonly"], hardlock: h["hardlock"],
                                       ins: h["ins"], logins: h["logins"].to_i, user_ref: h["user_ref"])
          end
        end

        # @see SQRL::Server::PendingLoginStore
        class PendingLoginStore < Base
          # Create on the cache store; same contract as +SQRL::Server::PendingLoginStore#create+.
          def create(id, ip:, return_to:, expires_at:, link_user_ref: nil, created_at: Time.now)
            login = SQRL::Server::PendingLogin.new(id: id, ip: ip, return_to: return_to, expires_at: expires_at,
                                                   link_user_ref: link_user_ref, created_at: created_at)
            write(login)
            login
          end

          # Find on the cache store; same contract as +SQRL::Server::IdentityStore#find+.
          def find(id)
            return nil if id.nil?

            data = @cache.read(key("login", id))
            return nil unless data

            login = load(data)
            # The cache TTL has a one-second floor; honour the exact expiry ourselves.
            login.expires_at && login.expires_at <= Time.now ? nil : login
          end

          # Update on the cache store; same contract as +SQRL::Server::IdentityStore#update+.
          def update(id, **attrs)
            login = find(id)
            return nil unless login

            old_token = login.cps_token
            attrs.each { |name, value| login[name] = value }
            write(login)
            if attrs.key?(:cps_token)
              @cache.delete(key("cps", old_token)) if old_token && old_token != login.cps_token
              if login.cps_token
                @cache.write(key("cps", login.cps_token), id, expires_in: ttl_until(login.cps_token_expires_at, Time.now))
              end
            end
            login
          end

          # Claim cps token on the cache store; same contract as +SQRL::Server::PendingLoginStore#claim_cps_token+.
          def claim_cps_token(token, now: Time.now)
            return nil if token.nil? || token.empty?

            id = @cache.read(key("cps", token))
            return nil unless id
            # The index entry is the single-use guard.
            return nil unless @cache.delete(key("cps", token))

            login = find(id)
            return nil unless login && login.cps_token == token

            expired = login.cps_token_expires_at && login.cps_token_expires_at <= now
            login.cps_token = nil
            login.cps_token_expires_at = nil
            write(login)
            expired ? nil : login
          end

          # Entries expire through the cache TTL.
          def prune!(_now = Time.now)
            nil
          end

          private

          def write(login)
            @cache.write(key("login", login.id), dump(login), expires_in: ttl_until(login.expires_at, Time.now))
          end

          def dump(l)
            { "id" => l.id, "authenticated_idk" => Codec.bin(l.authenticated_idk),
              "authenticated_at" => Codec.time(l.authenticated_at), "btn" => l.btn, "asked" => l.asked == true,
              "last_command" => l.last_command&.to_s, "cps_token" => l.cps_token,
              "cps_token_expires_at" => Codec.time(l.cps_token_expires_at), "ip" => l.ip, "return_to" => l.return_to,
              "link_user_ref" => l.link_user_ref, "created_at" => Codec.time(l.created_at),
              "expires_at" => Codec.time(l.expires_at), "ip_matched" => l.ip_matched == true }
          end

          def load(h)
            SQRL::Server::PendingLogin.new(id: h["id"], authenticated_idk: Codec.unbin(h["authenticated_idk"]),
                                           authenticated_at: Codec.untime(h["authenticated_at"]), btn: h["btn"],
                                           asked: h["asked"], last_command: h["last_command"]&.to_sym,
                                           cps_token: h["cps_token"],
                                           cps_token_expires_at: Codec.untime(h["cps_token_expires_at"]),
                                           ip: h["ip"], return_to: h["return_to"], link_user_ref: h["link_user_ref"],
                                           created_at: Codec.untime(h["created_at"]),
                                           expires_at: Codec.untime(h["expires_at"]), ip_matched: h["ip_matched"])
          end
        end
      end
    end
  end
end
