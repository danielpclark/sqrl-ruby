# frozen_string_literal: true

module SQRL
  module Rails
    # One login page view (+sqrl_pending_logins+), keyed by the opaque +login_id+ kept in
    # the browser session. Pruned by +sqrl:prune+.
    class PendingLogin < ::ActiveRecord::Base
      self.table_name = "sqrl_pending_logins"

      scope :expired, ->(now = Time.current) { where("expires_at <= ?", now) }

      def authenticated? = !authenticated_idk.nil?
    end
  end
end
