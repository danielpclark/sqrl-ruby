# frozen_string_literal: true

module SQRL
  module Rails
    # An issued nut (+sqrl_nuts+). Consumed at most once; pruned by +sqrl:prune+.
    class Nut < ::ActiveRecord::Base
      self.table_name = "sqrl_nuts"

      scope :unused, -> { where(used_at: nil) }
      scope :expired, ->(now = Time.current) { where("expires_at <= ?", now) }
    end
  end
end
