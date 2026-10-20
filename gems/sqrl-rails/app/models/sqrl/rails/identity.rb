# frozen_string_literal: true

module SQRL
  module Rails
    # A SQRL association (+sqrl_identities+). +idk+, +suk+ and +vuk+ are base64url.
    # Rows with +superseded_by+ set are tombstones left behind by a re-key.
    class Identity < ::ActiveRecord::Base
      self.table_name = "sqrl_identities"

      belongs_to :user, polymorphic: true, optional: true

      scope :active, -> { where(superseded_by: nil) }
      scope :superseded, -> { where.not(superseded_by: nil) }
      # Identities whose client asked the site to refuse non-SQRL authentication.
      scope :sqrl_only, -> { where(sqrlonly: true) }
      # Identities whose client asked the site to refuse non-SQRL account recovery.
      scope :hard_locked, -> { where(hardlock: true) }
      # Identities attached to a user record (or a +"Type:id"+ reference).
      scope :for_user, lambda { |user|
        ref = SQRL::Rails.user_ref(user)
        type, id = ref.to_s.split(":", 2)
        where(user_type: type, user_id: id)
      }

      validates :idk, presence: true, uniqueness: true

      def superseded? = !superseded_by.nil?

      # Raw +idk+ bytes.
      def idk_bytes = SQRL::Util.b64u_decode(idk)

      # A short, display-safe handle for the identity (the key is a public value, but a
      # full base64url key is unwieldy in a table).
      def short_idk = "#{idk[0, 12]}…"

      # The policy flags the client set, as words.
      #
      # @return [Array<String>]
      def flags
        list = []
        list << "disabled" if disabled
        list << "SQRL only" if sqrlonly
        list << "hard lock" if hardlock
        list
      end
    end
  end
end
