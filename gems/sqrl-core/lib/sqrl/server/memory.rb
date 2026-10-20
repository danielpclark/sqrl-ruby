# frozen_string_literal: true

module SQRL
  module Server
    # In-memory store implementations: thread-safe, process-local. Suitable for tests,
    # development and single-process demos; production deployments use a database-backed
    # implementation (see the framework gems).
    module Memory
      # @return [Stores] a fresh set of in-memory stores
      def self.stores
        Stores.new(nuts: NutStore.new, identities: IdentityStore.new, pending_logins: PendingLoginStore.new)
      end

      # @see Server::NutStore
      class NutStore < Server::NutStore
        def initialize
          super
          @mutex = Mutex.new
          @nuts = {}
        end

        # (see SQRL::Server::NutStore#issue)
        def issue(nut:, pending_login_id:, expected_server:, ip:, bound_idk:, expires_at:)
          record = NutRecord.new(nut: nut, pending_login_id: pending_login_id, expected_server: expected_server,
                                 ip: ip, bound_idk: bound_idk, expires_at: expires_at, used_at: nil)
          @mutex.synchronize { @nuts[nut] = record }
          record.dup
        end

        # (see SQRL::Server::NutStore#consume)
        def consume(nut, now: Time.now)
          @mutex.synchronize do
            record = @nuts[nut]
            return nil if record.nil? || record.used? || record.expired?(now)

            record.used_at = now
            record.dup
          end
        end

        # Remove expired records.
        # @return [Integer] number removed
        def prune!(now = Time.now)
          @mutex.synchronize { @nuts.delete_if { |_, r| r.used? || r.expired?(now) } }
          nil
        end

        # @return [Integer] number of records held
        def size
          @mutex.synchronize { @nuts.size }
        end
      end

      # @see Server::IdentityStore
      class IdentityStore < Server::IdentityStore
        def initialize
          super
          @mutex = Mutex.new
          @identities = {}
          @superseded = {}
        end

        # (see SQRL::Server::IdentityStore#find)
        def find(idk)
          @mutex.synchronize { @identities[idk.b]&.dup }
        end

        # (see SQRL::Server::IdentityStore#create)
        def create(**attrs)
          identity = Identity.new(**attrs)
          @mutex.synchronize do
            raise ArgumentError, "identity already exists" if @identities.key?(identity.idk.b)

            @identities[identity.idk.b] = identity
          end
          identity.dup
        end

        # (see SQRL::Server::IdentityStore#update)
        def update(idk, **attrs)
          @mutex.synchronize do
            identity = @identities[idk.b]
            return nil unless identity

            attrs.each { |k, v| identity[k] = v }
            identity.dup
          end
        end

        # (see SQRL::Server::IdentityStore#rekey)
        def rekey(old_idk, new_idk, suk:, vuk:, ins:)
          @mutex.synchronize do
            identity = @identities.delete(old_idk.b)
            return nil unless identity

            identity.idk = new_idk.b
            identity.suk = suk
            identity.vuk = vuk
            identity.ins = ins
            @identities[new_idk.b] = identity
            @superseded[old_idk.b] = new_idk.b
            identity.dup
          end
        end

        def superseded?(idk)
          @mutex.synchronize { @superseded.key?(idk.b) }
        end

        # (see SQRL::Server::IdentityStore#remove)
        def remove(idk)
          @mutex.synchronize { @identities.delete(idk.b) }
        end

        # @return [Integer] number of active identities
        def count
          @mutex.synchronize { @identities.size }
        end

        # @return [Array<Identity>] every active identity
        def all
          @mutex.synchronize { @identities.values.map(&:dup) }
        end
      end

      # @see Server::PendingLoginStore
      class PendingLoginStore < Server::PendingLoginStore
        def initialize
          super
          @mutex = Mutex.new
          @logins = {}
        end

        # (see SQRL::Server::IdentityStore#create)
        def create(id, ip:, return_to:, expires_at:, link_user_ref: nil, created_at: Time.now)
          login = PendingLogin.new(id: id, ip: ip, return_to: return_to, expires_at: expires_at,
                                   link_user_ref: link_user_ref, created_at: created_at)
          @mutex.synchronize { @logins[id] = login }
          login.dup
        end

        # (see SQRL::Server::IdentityStore#find)
        def find(id)
          @mutex.synchronize { @logins[id]&.dup }
        end

        # (see SQRL::Server::IdentityStore#update)
        def update(id, **attrs)
          @mutex.synchronize do
            login = @logins[id]
            return nil unless login

            attrs.each { |k, v| login[k] = v }
            login.dup
          end
        end

        # (see SQRL::Server::PendingLoginStore#claim_cps_token)
        def claim_cps_token(token, now: Time.now)
          return nil if token.nil? || token.empty?

          @mutex.synchronize do
            login = @logins.values.find { |l| l.cps_token && Util.secure_compare(l.cps_token, token) }
            return nil unless login

            expired = login.cps_token_expires_at && login.cps_token_expires_at <= now
            login.cps_token = nil
            login.cps_token_expires_at = nil
            expired ? nil : login.dup
          end
        end

        # Remove expired records.
        # @return [Integer] number removed
        def prune!(now = Time.now)
          @mutex.synchronize { @logins.delete_if { |_, l| l.expired?(now) } }
          nil
        end

        # @return [Integer] number of records held
        def size
          @mutex.synchronize { @logins.size }
        end
      end
    end
  end
end
