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

      validates :idk, presence: true, uniqueness: true

      def superseded? = !superseded_by.nil?

      # Raw +idk+ bytes.
      def idk_bytes = SQRL::Util.b64u_decode(idk)
    end
  end
end
