# frozen_string_literal: true

require "json"

module SQRL
  module Server
    # Redis-backed store implementations for sites that run several processes without a
    # relational database (Sinatra, Roda, bare Rack, ...).
    #
    #   require "sqrl/server/redis"
    #   stores = SQRL::Server::Redis.stores(redis: ::Redis.new(url: ENV["REDIS_URL"]))
    #
    # Needs the +redis+ gem (not a dependency of sqrl-core; add it to your Gemfile) and a
    # Redis server of version 2.6 or later (Lua scripting). Atomicity:
    #
    # * a nut is consumed with +GETDEL+ (Redis 6.2+) or an equivalent Lua script, so
    #   exactly one of any number of concurrent consumers wins;
    # * a CPS token is claimed by a Lua script that checks the token index against the
    #   pending login and clears both in one step;
    # * a re-key renames the identity hash and records the superseded key in one script.
    #
    # Nuts and pending logins carry Redis TTLs derived from their +expires_at+, so they
    # vanish on their own; +prune!+ still exists for records that were given no expiry.
    # Binary values (identity keys, lock keys) are stored base64url-encoded. All keys live
    # under +namespace+ (default "sqrl"), separated by colons; the keys a single script
    # touches share that prefix, which Redis Cluster users should turn into a hash tag
    # (for example "{sqrl}").
    module Redis
      # @param redis [::Redis] a connected client from the +redis+ gem (or any object
      #   speaking the same method API)
      # @param namespace [String] key prefix
      # @param default_ttl [Integer] seconds to keep records that were given no expiry
      # @return [Stores]
      def self.stores(redis:, namespace: "sqrl", default_ttl: 24 * 3600)
        Stores.new(nuts: NutStore.new(redis, namespace: namespace, default_ttl: default_ttl),
                   identities: IdentityStore.new(redis, namespace: namespace),
                   pending_logins: PendingLoginStore.new(redis, namespace: namespace, default_ttl: default_ttl))
      end

      # Connect with the +redis+ gem and build the stores.
      #
      # @param url [String] a redis:// URL
      def self.connect(url = ENV.fetch("REDIS_URL", "redis://127.0.0.1:6379/0"), **options)
        begin
          require "redis"
        rescue LoadError
          raise SQRL::Error, "SQRL::Server::Redis needs the redis gem: add `gem \"redis\"` to your Gemfile"
        end
        stores(redis: ::Redis.new(url: url), **options)
      end

      # Lua scripts. The first line of each is a tag the in-process test double uses to
      # dispatch; Redis ignores it as a comment.
      module Scripts
        # Fallback for +GETDEL+ on Redis servers older than 6.2.
        GETDEL = <<~LUA
          -- sqrl:getdel
          local v = redis.call('GET', KEYS[1])
          if v then redis.call('DEL', KEYS[1]) end
          return v
        LUA

        # Create an identity hash only when the key does not exist yet.
        CREATE_IDENTITY = <<~LUA
          -- sqrl:create
          if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
          redis.call('HSET', KEYS[1], unpack(ARGV))
          return 1
        LUA

        # Delete an identity hash and its superseded marker.
        REMOVE_IDENTITY = <<~LUA
          -- sqrl:remove
          local v = redis.call('HGETALL', KEYS[1])
          if #v == 0 then return false end
          redis.call('DEL', KEYS[1])
          return v
        LUA

        # KEYS: old hash, new hash, superseded set. ARGV: new idk, suk, vuk, ins ("" = none), old idk.
        REKEY = <<~LUA
          -- sqrl:rekey
          if redis.call('EXISTS', KEYS[1]) == 0 then return false end
          redis.call('RENAME', KEYS[1], KEYS[2])
          redis.call('HSET', KEYS[2], 'idk', ARGV[1], 'suk', ARGV[2], 'vuk', ARGV[3])
          if ARGV[4] == '' then
            redis.call('HDEL', KEYS[2], 'ins')
          else
            redis.call('HSET', KEYS[2], 'ins', ARGV[4])
          end
          redis.call('SADD', KEYS[3], ARGV[5])
          return redis.call('HGETALL', KEYS[2])
        LUA

        # KEYS: token index key. ARGV: pending-login key prefix, token.
        # Returns [cps_token_expires_at or "", login id, field, value, field, value, ...].
        CLAIM = <<~LUA
          -- sqrl:claim
          local id = redis.call('GET', KEYS[1])
          if not id then return false end
          redis.call('DEL', KEYS[1])
          local pl = ARGV[1] .. id
          local tok = redis.call('HGET', pl, 'cps_token')
          if tok ~= ARGV[2] then return false end
          local exp = redis.call('HGET', pl, 'cps_token_expires_at') or ''
          redis.call('HDEL', pl, 'cps_token', 'cps_token_expires_at')
          local data = redis.call('HGETALL', pl)
          table.insert(data, 1, id)
          table.insert(data, 1, exp)
          return data
        LUA
      end

      # Encoding helpers shared by the three stores.
      module Codec
        module_function

        # @return [String, nil] a Time encoded as epoch seconds
        def time_out(time) = time.nil? ? nil : format("%.6f", time.to_f)
        # @return [Time, nil] a Time decoded from epoch seconds
        def time_in(str) = str.nil? || str.empty? ? nil : Time.at(Float(str))
        # @return [String] a boolean encoded for Redis
        def bool_out(value) = value ? "1" : "0"
        # @return [Boolean] a boolean decoded from Redis
        def bool_in(str) = str == "1"
        # @return [String, nil] binary bytes encoded for Redis (base64url)
        def bin_out(bytes) = bytes.nil? ? nil : Util.b64u_encode(bytes)
        # @return [String, nil] binary bytes decoded from Redis
        def bin_in(str) = str.nil? || str.empty? ? nil : Util.b64u_decode(str)

        # Milliseconds until +time+, at least 1 (Redis rejects non-positive TTLs).
        def ttl_ms(time, default_seconds)
          return default_seconds * 1000 if time.nil?

          [((time.to_f - Time.now.to_f) * 1000).ceil, 1].max
        end

        # @return [Hash] a flat Redis field/value list as a Hash
        def pairs_to_hash(flat)
          return nil if flat.nil? || flat == false
          return flat if flat.is_a?(Hash)

          Hash[*flat]
        end
      end

      # Common plumbing.
      class Base
        def initialize(redis, namespace:)
          @redis = redis
          @ns = namespace
        end

        private

        def key(kind, id) = "#{@ns}:#{kind}:#{id}"

        def each_key(kind, &)
          @redis.scan_each(match: "#{@ns}:#{kind}:*", &)
        end
      end

      # @see Server::NutStore
      class NutStore < Base
        def initialize(redis, namespace:, default_ttl:)
          super(redis, namespace: namespace)
          @default_ttl = default_ttl
        end

        # (see SQRL::Server::NutStore#issue)
        def issue(nut:, pending_login_id:, expected_server:, ip:, bound_idk:, expires_at:)
          payload = JSON.generate("pl" => pending_login_id, "srv" => expected_server, "ip" => ip,
                                  "idk" => Codec.bin_out(bound_idk), "exp" => Codec.time_out(expires_at))
          @redis.set(key(:nut, nut), payload, px: Codec.ttl_ms(expires_at, @default_ttl))
          NutRecord.new(nut: nut, pending_login_id: pending_login_id, expected_server: expected_server, ip: ip,
                        bound_idk: bound_idk, expires_at: expires_at, used_at: nil)
        end

        # (see SQRL::Server::NutStore#consume)
        def consume(nut, now: Time.now)
          return nil if nut.nil? || nut.empty?

          payload = getdel(key(:nut, nut))
          return nil unless payload

          data = JSON.parse(payload)
          record = NutRecord.new(nut: nut, pending_login_id: data["pl"], expected_server: data["srv"], ip: data["ip"],
                                 bound_idk: Codec.bin_in(data["idk"]), expires_at: Codec.time_in(data["exp"]),
                                 used_at: now)
          record.expired?(now) ? nil : record
        end

        # Used nuts are deleted when consumed and expiry is enforced by Redis TTLs; this
        # only removes records whose stored +expires_at+ has passed.
        def prune!(now = Time.now)
          each_key(:nut) do |k|
            payload = @redis.get(k)
            next unless payload

            exp = Codec.time_in(JSON.parse(payload)["exp"])
            @redis.del(k) if exp && exp <= now
          end
          nil
        end

        private

        def getdel(k)
          @redis.getdel(k)
        rescue StandardError => e
          raise unless e.class.name.to_s.include?("CommandError")

          # Redis < 6.2: emulate GETDEL atomically with a script.
          @redis.eval(Scripts::GETDEL, keys: [k])
        end
      end

      # @see Server::IdentityStore
      class IdentityStore < Base
        # Hash fields of an identity record.
        FIELDS = %i[idk suk vuk disabled sqrlonly hardlock ins logins user_ref].freeze

        # (see SQRL::Server::IdentityStore#find)
        def find(idk)
          to_identity(@redis.hgetall(key(:id, Util.b64u_encode(idk))))
        end

        def create(**attrs)
          identity = Identity.new(**attrs)
          fields = encode(identity.to_h).compact.flatten
          created = @redis.eval(Scripts::CREATE_IDENTITY, keys: [key(:id, identity.idk_b64)], argv: fields)
          raise ArgumentError, "identity already exists" unless created.to_i == 1

          identity.dup
        end

        # (see SQRL::Server::IdentityStore#update)
        def update(idk, **attrs)
          k = key(:id, Util.b64u_encode(idk))
          return nil unless @redis.exists?(k)

          encoded = encode(attrs)
          removals = encoded.select { |_, v| v.nil? }.keys
          writes = encoded.compact
          @redis.hdel(k, *removals) unless removals.empty?
          @redis.hset(k, writes) unless writes.empty?
          find(idk)
        end

        # (see SQRL::Server::IdentityStore#rekey)
        def rekey(old_idk, new_idk, suk:, vuk:, ins:)
          old_b64 = Util.b64u_encode(old_idk)
          new_b64 = Util.b64u_encode(new_idk)
          flat = @redis.eval(Scripts::REKEY,
                             keys: [key(:id, old_b64), key(:id, new_b64), "#{@ns}:superseded"],
                             argv: [new_b64, Util.b64u_encode(suk), Util.b64u_encode(vuk), ins.to_s, old_b64])
          to_identity(Codec.pairs_to_hash(flat))
        end

        def superseded?(idk)
          @redis.sismember("#{@ns}:superseded", Util.b64u_encode(idk)) ? true : false
        end

        # (see SQRL::Server::IdentityStore#remove)
        def remove(idk)
          flat = @redis.eval(Scripts::REMOVE_IDENTITY, keys: [key(:id, Util.b64u_encode(idk))])
          to_identity(Codec.pairs_to_hash(flat))
        end

        private

        def encode(attrs)
          attrs.to_h do |k, v|
            k = k.to_sym
            raise ArgumentError, "unknown identity attribute #{k}" unless FIELDS.include?(k)

            value =
              case k
              when :idk, :suk, :vuk then Codec.bin_out(v)
              when :disabled, :sqrlonly, :hardlock then Codec.bool_out(v)
              when :logins then v.nil? ? nil : v.to_i.to_s
              else v&.to_s
              end
            [k.to_s, value]
          end
        end

        def to_identity(hash)
          return nil if hash.nil? || hash.empty?

          Identity.new(idk: Codec.bin_in(hash["idk"]), suk: Codec.bin_in(hash["suk"]), vuk: Codec.bin_in(hash["vuk"]),
                       disabled: Codec.bool_in(hash["disabled"]), sqrlonly: Codec.bool_in(hash["sqrlonly"]),
                       hardlock: Codec.bool_in(hash["hardlock"]), ins: hash["ins"], logins: hash["logins"].to_i,
                       user_ref: hash["user_ref"])
        end
      end

      # @see Server::PendingLoginStore
      class PendingLoginStore < Base
        # Hash fields of a pending-login record.
        FIELDS = %i[authenticated_idk authenticated_at btn asked last_command cps_token cps_token_expires_at
                    ip return_to link_user_ref created_at expires_at ip_matched].freeze

        def initialize(redis, namespace:, default_ttl:)
          super(redis, namespace: namespace)
          @default_ttl = default_ttl
        end

        # (see SQRL::Server::PendingLoginStore#create)
        def create(id, ip:, return_to:, expires_at:, link_user_ref: nil, created_at: Time.now)
          login = PendingLogin.new(id: id, ip: ip, return_to: return_to, expires_at: expires_at,
                                   link_user_ref: link_user_ref, created_at: created_at)
          k = key(:pl, id)
          @redis.del(k)
          @redis.hset(k, encode(login.to_h.except(:id)).compact)
          @redis.pexpire(k, Codec.ttl_ms(expires_at, @default_ttl))
          login.dup
        end

        # (see SQRL::Server::IdentityStore#find)
        def find(id)
          return nil if id.nil?

          to_login(id, @redis.hgetall(key(:pl, id)))
        end

        # (see SQRL::Server::IdentityStore#update)
        def update(id, **attrs)
          k = key(:pl, id)
          return nil unless @redis.exists?(k)

          reindex_token(id, k, attrs) if attrs.key?(:cps_token)
          encoded = encode(attrs)
          removals = encoded.select { |_, v| v.nil? }.keys
          writes = encoded.compact
          @redis.hdel(k, *removals) unless removals.empty?
          @redis.hset(k, writes) unless writes.empty?
          @redis.pexpire(k, Codec.ttl_ms(attrs[:expires_at], @default_ttl)) if attrs.key?(:expires_at)
          find(id)
        end

        # (see SQRL::Server::PendingLoginStore#claim_cps_token)
        def claim_cps_token(token, now: Time.now)
          return nil if token.nil? || token.empty?

          flat = @redis.eval(Scripts::CLAIM, keys: [key(:cps, token)], argv: ["#{@ns}:pl:", token])
          return nil unless flat.is_a?(Array) && !flat.empty?

          expires_at = Codec.time_in(flat[0])
          id = flat[1]
          hash = Codec.pairs_to_hash(flat.drop(2))
          return nil if expires_at && expires_at <= now

          to_login(id, hash)
        end

        # Remove expired records (Redis TTLs do most of this already).
        # @return [Integer] number removed
        def prune!(now = Time.now)
          each_key(:pl) do |k|
            exp = Codec.time_in(@redis.hget(k, "expires_at"))
            @redis.del(k) if exp && exp <= now
          end
          nil
        end

        private

        # Keep the token → login index in step with the +cps_token+ field.
        def reindex_token(id, k, attrs)
          old = @redis.hget(k, "cps_token")
          @redis.del(key(:cps, old)) if old && !old.empty?
          new = attrs[:cps_token]
          return if new.nil? || new.empty?

          expires_at = if attrs.key?(:cps_token_expires_at)
                         attrs[:cps_token_expires_at]
                       else
                         Codec.time_in(@redis.hget(k,
                                                   "cps_token_expires_at"))
                       end
          # The index outlives the token's own expiry by a minute so that a late claim still
          # finds the login and clears the stale token (the expiry itself is enforced by
          # value in claim_cps_token).
          @redis.set(key(:cps, new), id, px: Codec.ttl_ms(expires_at, @default_ttl) + 60_000)
        end

        def encode(attrs)
          attrs.to_h do |f, v|
            f = f.to_sym
            raise ArgumentError, "unknown pending login attribute #{f}" unless FIELDS.include?(f) || f == :id

            value =
              case f
              when :authenticated_idk then Codec.bin_out(v)
              when :authenticated_at, :cps_token_expires_at, :created_at, :expires_at then Codec.time_out(v)
              when :asked, :ip_matched then Codec.bool_out(v)
              when :btn then v&.to_i&.to_s
              else v&.to_s
              end
            [f.to_s, value]
          end
        end

        def to_login(id, hash)
          return nil if hash.nil? || hash.empty?

          PendingLogin.new(id: id, ip: hash["ip"], return_to: hash["return_to"], link_user_ref: hash["link_user_ref"],
                           created_at: Codec.time_in(hash["created_at"]), expires_at: Codec.time_in(hash["expires_at"]),
                           authenticated_idk: Codec.bin_in(hash["authenticated_idk"]),
                           authenticated_at: Codec.time_in(hash["authenticated_at"]),
                           btn: hash["btn"]&.to_i, asked: Codec.bool_in(hash["asked"]),
                           last_command: hash["last_command"]&.to_sym, cps_token: hash["cps_token"],
                           cps_token_expires_at: Codec.time_in(hash["cps_token_expires_at"]),
                           ip_matched: Codec.bool_in(hash["ip_matched"]))
        end
      end
    end
  end
end
