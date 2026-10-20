# frozen_string_literal: true

ENV["RAILS_ENV"] = "test"
ENV["DATABASE_URL"] ||= "sqlite3::memory:"

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../sqrl-core/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../sqrl-rack/lib", __dir__)

require "bundler/setup"
require_relative "dummy/config/application"
Rails.application.initialize!

require "rack/test"
require "erb"

# Build the schema: the gem's own migration (through its generator template) plus the
# dummy app's users and sessions tables.
module DummySchema
  TEMPLATE = File.expand_path("../lib/generators/sqrl/install/templates/create_sqrl_tables.rb.tt", __dir__)

  def self.migration_version
    "[#{ActiveRecord::VERSION::STRING.to_f}]"
  end

  def self.load!
    ActiveRecord::Migration.verbose = false
    ActiveRecord::Schema.define do
      create_table :users, force: true do |t|
        t.string :name
        t.string :email_address
        t.string :password_digest
        t.timestamps
      end
      create_table :sessions, force: true do |t|
        t.references :user, null: false
        t.string :ip_address
        t.string :user_agent
        t.timestamps
      end
    end
    eval(ERB.new(File.read(TEMPLATE), trim_mode: "-").result(binding), binding, TEMPLATE) # rubocop:disable Security/Eval
    CreateSQRLTables.migrate(:up)
  end
end
DummySchema.load!

Dir[File.expand_path("support/**/*.rb", __dir__)].sort.each { |f| require f }

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed

  config.before do
    SQRL::Rails.reset!
    %w[sqrl_identities sqrl_nuts sqrl_pending_logins sessions users].each do |table|
      ActiveRecord::Base.connection.execute("DELETE FROM #{table}")
    end
    cfg = SQRL::Rails.config
    cfg.host = nil
    cfg.scheme = nil
    cfg.on_unknown_identity = :create
    cfg.sign_in = nil
    cfg.after_sign_in = nil
    cfg.find_user = nil
    cfg.create_user = nil
    cfg.current_user = nil
    cfg.failure_path = nil
    cfg.stores = :active_record
    cfg.require_ip_match = true
    cfg.ask = nil
    cfg.sin = nil
    cfg.nut_ttl = 300
    cfg.cps_token_ttl = 60
    cfg.clock = nil
  end
end
