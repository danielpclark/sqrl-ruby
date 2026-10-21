# frozen_string_literal: true

module SQRL
  module Server
    # One SQRL association (an +idk+) known to this site.
    #
    # +user_ref+ is opaque to the protocol: the framework integration uses it to point at
    # its own user record.
    Identity = Struct.new(:idk, :suk, :vuk, :disabled, :sqrlonly, :hardlock, :ins, :logins, :user_ref,
                          keyword_init: true) do
      def initialize(idk:, suk:, vuk:, disabled: false, sqrlonly: false, hardlock: false, ins: nil,
                     logins: 0, user_ref: nil)
        super
      end

      def disabled? = disabled ? true : false
      def sqrlonly? = sqrlonly ? true : false
      def hardlock? = hardlock ? true : false

      # +idk+ as base64url (the wire and storage-friendly form).
      def idk_b64 = Util.b64u_encode(idk)

      # @return [String] a short description with secret material redacted
      def inspect
        "#<SQRL::Server::Identity idk=#{idk_b64} disabled=#{disabled?} logins=#{logins}>"
      end
    end

    # A nut issued by the server: one per login page and one per response.
    NutRecord = Struct.new(:nut, :pending_login_id, :expected_server, :ip, :bound_idk, :expires_at, :used_at,
                           keyword_init: true) do
      def used? = !used_at.nil?

      def expired?(now)
        !expires_at.nil? && expires_at <= now
      end

      # @return [String] a short description with secret material redacted
      def inspect
        "#<SQRL::Server::NutRecord pending_login=#{pending_login_id} used=#{used?}>"
      end
    end

    # One login attempt as seen from a browser: created when the login page is rendered
    # (its id lives in the browser's session), authenticated by the SQRL client, and
    # completed either through the CPS callback (one-time +cps_token+) or by polling.
    # +ip_matched+ records whether the request that authenticated this login came from
    # the IP that requested the login page (TIF +IPS_MATCHED+). Completions that rely on
    # the browser's own cookie (the poll path) should require it, because a client that
    # sent +noiptest+ may have been tricked into authenticating a login page it did not
    # open; CPS completions do not need it, since the token lands in the client's own
    # browser.
    PendingLogin = Struct.new(:id, :authenticated_idk, :authenticated_at, :btn, :asked, :last_command,
                              :cps_token, :cps_token_expires_at, :ip, :return_to, :link_user_ref,
                              :created_at, :expires_at, :ip_matched, keyword_init: true) do
      def initialize(id:, ip: nil, return_to: nil, link_user_ref: nil, created_at: nil, expires_at: nil,
                     authenticated_idk: nil, authenticated_at: nil, btn: nil, asked: false, last_command: nil,
                     cps_token: nil, cps_token_expires_at: nil, ip_matched: false)
        super
      end

      def authenticated? = !authenticated_idk.nil?
      def asked? = asked ? true : false

      # Whether the SQRL client completed this login in CPS mode (a one-time +url=+ token was
      # issued). Such a login may only be completed by the browser that presents that token,
      # never through the poll. The token field stays set until the token is claimed, so an
      # unclaimed or expired token keeps the poll closed, as the specification requires.
      def cps? = !cps_token.nil?

      def expired?(now)
        !expires_at.nil? && expires_at <= now
      end
      # @return [String] a short description with secret material redacted

      def inspect
        "#<SQRL::Server::PendingLogin id=#{id} authenticated=#{authenticated?}>"
      end
    end

    # The three stores a {Handler} needs.
    Stores = Struct.new(:nuts, :identities, :pending_logins, keyword_init: true)

    # Interface for nut storage. Nuts are issued per login page and per response and
    # must be consumed exactly once; +consume+ has to be atomic (compare-and-set or an
    # +UPDATE ... WHERE used_at IS NULL+ that reports whether it changed a row).
    class NutStore
      # Record a freshly issued nut.
      #
      # @param nut [String]
      # @param pending_login_id [String]
      # @param expected_server [String] the exact +server=+ value the next request must echo
      # @param ip [String] client IP that received the nut
      # @param bound_idk [String, nil] identity the transaction is bound to (raw bytes)
      # @param expires_at [Time, nil]
      # @return [NutRecord]
      def issue(nut:, pending_login_id:, expected_server:, ip:, bound_idk:, expires_at:)
        raise NotImplementedError
      end

      # Atomically mark the nut used and return its record, or nil when it is unknown,
      # already used or expired.
      #
      # @return [NutRecord, nil]
      def consume(nut, now: Time.now)
        raise NotImplementedError
      end

      # Delete expired and used nuts.
      def prune!(now = Time.now)
        raise NotImplementedError
      end
    end

    # Interface for identity (SQRL association) storage, keyed by raw +idk+ bytes.
    class IdentityStore
      # @return [Identity, nil]
      def find(idk)
        raise NotImplementedError
      end

      # @param attrs [Hash] keyword attributes of {Identity}
      # @return [Identity]
      def create(**attrs)
        raise NotImplementedError
      end

      # Merge +attrs+ into the stored identity.
      #
      # @return [Identity, nil]
      def update(idk, **attrs)
        raise NotImplementedError
      end

      # Move the association from +old_idk+ to +new_idk+ with the new lock values and
      # mark +old_idk+ superseded.
      #
      # @return [Identity, nil] the re-keyed identity, or nil when +old_idk+ is unknown
      def rekey(old_idk, new_idk, suk:, vuk:, ins:)
        raise NotImplementedError
      end

      # Whether +idk+ was superseded by a re-key.
      def superseded?(idk)
        raise NotImplementedError
      end

      # Delete the association. Returns the removed identity or nil.
      def remove(idk)
        raise NotImplementedError
      end
    end

    # Interface for pending-login storage, keyed by the opaque id kept in the browser
    # session. +claim_cps_token+ must be atomic.
    class PendingLoginStore
      # @return [PendingLogin]
      def create(id, ip:, return_to:, expires_at:, link_user_ref: nil, created_at: Time.now)
        raise NotImplementedError
      end

      # @return [PendingLogin, nil]
      def find(id)
        raise NotImplementedError
      end

      # Merge +attrs+ into the pending login.
      #
      # @return [PendingLogin, nil]
      def update(id, **attrs)
        raise NotImplementedError
      end

      # Atomically clear and return the pending login holding this CPS token, or nil
      # when the token is unknown, already claimed or expired.
      #
      # @return [PendingLogin, nil]
      def claim_cps_token(token, now: Time.now)
        raise NotImplementedError
      end

      # Delete expired pending logins.
      def prune!(now = Time.now)
        raise NotImplementedError
      end
    end
  end
end
