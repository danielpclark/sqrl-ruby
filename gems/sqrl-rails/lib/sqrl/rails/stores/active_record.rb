# frozen_string_literal: true

module SQRL
  module Rails
    module Stores
      # ActiveRecord-backed implementations of the three {SQRL::Server} store interfaces,
      # over the tables created by `bin/rails generate sqrl:install`:
      #
      # * +sqrl_identities+ – one row per SQRL association; +idk+, +suk+ and +vuk+ are
      #   stored base64url-encoded; a re-key updates the row in place and leaves a
      #   tombstone row for the old +idk+ with +superseded_by+ set.
      # * +sqrl_nuts+ – issued nuts; +consume+ is a single conditional +UPDATE+, so a nut
      #   can only ever be used once even under concurrent requests.
      # * +sqrl_pending_logins+ – one row per login page view; +claim_cps_token+ is a
      #   compare-and-set on the token.
      #
      # Key material crosses the boundary as raw bytes (what the protocol core uses) and
      # is encoded/decoded here.
      module ActiveRecord
        # @return [SQRL::Server::Stores]
        def self.stores
          SQRL::Server::Stores.new(nuts: NutStore.new, identities: IdentityStore.new,
                                   pending_logins: PendingLoginStore.new)
        end

        # Runs a store operation with an explicitly checked-out connection, returned to
        # the pool as soon as it finishes (Rails 7.1 would otherwise keep a thread's
        # implicit connection until the thread dies, starving concurrent callers).
        module WithConnection
          private

          def with_connection(&)
            ::ActiveRecord::Base.connection_pool.with_connection(&)
          end
        end

        # Encoding helpers shared by the stores.
        module Codec
          module_function

          # @return [String, nil] binary bytes as base64url for a string column
          def encode(bytes)
            bytes.nil? ? nil : SQRL::Util.b64u_encode(bytes.b)
          end

          # @return [String, nil] binary bytes from a base64url column
          def decode(text)
            text.nil? || text.empty? ? nil : SQRL::Util.b64u_decode(text)
          end
        end

        # @see SQRL::Server::NutStore
        class NutStore < SQRL::Server::NutStore
          include WithConnection

          # Issue on ActiveRecord; same contract as +SQRL::Server::NutStore#issue+.
          def issue(nut:, pending_login_id:, expected_server:, ip:, bound_idk:, expires_at:)
            with_connection do
              row = Nut.create!(nut: nut, pending_login_id: pending_login_id, expected_server: expected_server, ip: ip,
                                bound_idk: Codec.encode(bound_idk), expires_at: expires_at)
              to_record(row)
            end
          end

          # Consume on ActiveRecord; same contract as +SQRL::Server::NutStore#consume+.
          def consume(nut, now: Time.now)
            return nil if nut.nil? || nut.empty?

            with_connection do
              scope = Nut.where(nut: nut, used_at: nil).where("expires_at IS NULL OR expires_at > ?", now)
              next nil unless scope.update_all(used_at: now) == 1

              to_record(Nut.find_by!(nut: nut))
            end
          end

          # Delete expired rows.
          # @return [Integer] number deleted
          def prune!(now = Time.now)
            with_connection { Nut.where("used_at IS NOT NULL OR expires_at <= ?", now).delete_all }
            nil
          end

          private

          def to_record(row)
            SQRL::Server::NutRecord.new(nut: row.nut, pending_login_id: row.pending_login_id,
                                        expected_server: row.expected_server, ip: row.ip,
                                        bound_idk: Codec.decode(row.bound_idk), expires_at: row.expires_at,
                                        used_at: row.used_at)
          end
        end

        # @see SQRL::Server::IdentityStore
        class IdentityStore < SQRL::Server::IdentityStore
          # Identity columns that +update+ may change.
          ATTRIBUTE_COLUMNS = %i[suk vuk disabled sqrlonly hardlock ins logins].freeze

          # Find on ActiveRecord; same contract as +SQRL::Server::IdentityStore#find+.
          def find(idk)
            row = Identity.active.find_by(idk: Codec.encode(idk))
            row && to_record(row)
          end

          # Create on ActiveRecord; same contract as +SQRL::Server::IdentityStore#create+.
          def create(**attrs)
            identity = SQRL::Server::Identity.new(**attrs)
            row = Identity.new(idk: Codec.encode(identity.idk), suk: Codec.encode(identity.suk),
                               vuk: Codec.encode(identity.vuk), disabled: identity.disabled?,
                               sqrlonly: identity.sqrlonly?, hardlock: identity.hardlock?, ins: identity.ins,
                               logins: identity.logins.to_i, last_login_at: Time.current)
            assign_user(row, identity.user_ref)
            begin
              row.save!
            rescue ::ActiveRecord::RecordInvalid, ::ActiveRecord::RecordNotUnique
              raise ArgumentError, "identity already exists" if Identity.exists?(idk: row.idk)

              raise
            end
            to_record(row)
          end

          # Update on ActiveRecord; same contract as +SQRL::Server::IdentityStore#update+.
          def update(idk, **attrs)
            row = Identity.active.find_by(idk: Codec.encode(idk))
            return nil unless row

            changes = {}
            attrs.each do |key, value|
              case key
              when :suk, :vuk then changes[key] = Codec.encode(value)
              when :idk then changes[key] = Codec.encode(value)
              when :user_ref then assign_user(row, value)
              when *ATTRIBUTE_COLUMNS then changes[key] = value
              else raise ArgumentError, "unknown identity attribute #{key}"
              end
            end
            changes[:last_login_at] = Time.current if attrs.key?(:logins)
            row.assign_attributes(changes)
            row.save!
            to_record(row)
          end

          # Rekey on ActiveRecord; same contract as +SQRL::Server::IdentityStore#rekey+.
          def rekey(old_idk, new_idk, suk:, vuk:, ins:)
            old_b64 = Codec.encode(old_idk)
            new_b64 = Codec.encode(new_idk)
            Identity.transaction do
              row = Identity.active.lock.find_by(idk: old_b64)
              return nil unless row

              row.update!(idk: new_b64, suk: Codec.encode(suk), vuk: Codec.encode(vuk), ins: ins)
              Identity.create!(idk: old_b64, superseded_by: new_b64, disabled: true)
              to_record(row)
            end
          end

          def superseded?(idk)
            Identity.where(idk: Codec.encode(idk)).where.not(superseded_by: nil).exists?
          end

          # Remove on ActiveRecord; same contract as +SQRL::Server::IdentityStore#remove+.
          def remove(idk)
            row = Identity.active.find_by(idk: Codec.encode(idk))
            return nil unless row

            record = to_record(row)
            row.destroy!
            record
          end

          # The ActiveRecord row for an identity record (for applications).
          def row_for(identity)
            Identity.active.find_by(idk: identity.respond_to?(:idk_b64) ? identity.idk_b64 : identity.to_s)
          end

          private

          def assign_user(row, user_ref)
            if user_ref.nil?
              row.user_type = nil
              row.user_id = nil
            else
              type, id = user_ref.to_s.split(":", 2)
              row.user_type = type
              row.user_id = id
            end
          end

          def to_record(row)
            SQRL::Server::Identity.new(idk: Codec.decode(row.idk), suk: Codec.decode(row.suk),
                                       vuk: Codec.decode(row.vuk), disabled: row.disabled, sqrlonly: row.sqrlonly,
                                       hardlock: row.hardlock, ins: row.ins, logins: row.logins.to_i,
                                       user_ref: row.user_type && row.user_id ? "#{row.user_type}:#{row.user_id}" : nil)
          end
        end

        # @see SQRL::Server::PendingLoginStore
        class PendingLoginStore < SQRL::Server::PendingLoginStore
          include WithConnection

          # Pending-login columns that +update+ may change.
          COLUMNS = %i[authenticated_at btn asked ip return_to link_user_ref expires_at cps_token
                       cps_token_expires_at ip_matched].freeze

          # Create on ActiveRecord; same contract as +SQRL::Server::PendingLoginStore#create+.
          def create(id, ip:, return_to:, expires_at:, link_user_ref: nil, created_at: Time.now)
            row = PendingLogin.create!(login_id: id, ip: ip, return_to: return_to, expires_at: expires_at,
                                       link_user_ref: link_user_ref, created_at: created_at)
            to_record(row)
          end

          # Find on ActiveRecord; same contract as +SQRL::Server::IdentityStore#find+.
          def find(id)
            row = id && PendingLogin.find_by(login_id: id)
            row && to_record(row)
          end

          # Update on ActiveRecord; same contract as +SQRL::Server::IdentityStore#update+.
          def update(id, **attrs)
            row = PendingLogin.find_by(login_id: id)
            return nil unless row

            changes = {}
            attrs.each do |key, value|
              case key
              when :authenticated_idk then changes[key] = Codec.encode(value)
              when :last_command then changes[key] = value&.to_s
              when *COLUMNS then changes[key] = value
              else raise ArgumentError, "unknown pending login attribute #{key}"
              end
            end
            row.update!(changes)
            to_record(row)
          end

          # Claim cps token on ActiveRecord; same contract as +SQRL::Server::PendingLoginStore#claim_cps_token+.
          def claim_cps_token(token, now: Time.now)
            return nil if token.nil? || token.empty?

            with_connection do
              row = PendingLogin.find_by(cps_token: token)
              next nil unless row

              claimed = PendingLogin.where(id: row.id, cps_token: token)
                                    .update_all(cps_token: nil, cps_token_expires_at: nil) == 1
              next nil unless claimed
              next nil if row.cps_token_expires_at && row.cps_token_expires_at <= now

              row.cps_token = nil
              row.cps_token_expires_at = nil
              to_record(row)
            end
          end

          # Delete expired rows.
          # @return [Integer] number deleted
          def prune!(now = Time.now)
            PendingLogin.where("expires_at <= ?", now).delete_all
            nil
          end

          private

          def to_record(row)
            SQRL::Server::PendingLogin.new(
              id: row.login_id, ip: row.ip, return_to: row.return_to, link_user_ref: row.link_user_ref,
              created_at: row.created_at, expires_at: row.expires_at,
              authenticated_idk: Codec.decode(row.authenticated_idk), authenticated_at: row.authenticated_at,
              btn: row.btn, asked: row.asked, last_command: row.last_command&.to_sym,
              cps_token: row.cps_token, cps_token_expires_at: row.cps_token_expires_at,
              ip_matched: row.respond_to?(:ip_matched) ? row.ip_matched == true : false
            )
          end
        end
      end
    end
  end
end
