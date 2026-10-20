# frozen_string_literal: true

namespace :sqrl do
  desc "Delete expired SQRL nuts and pending logins"
  task prune: :environment do
    stores = SQRL::Rails.stores
    now = Time.current
    stores.nuts.prune!(now)
    stores.pending_logins.prune!(now)
    puts "SQRL: pruned expired nuts and pending logins"
  end
end
