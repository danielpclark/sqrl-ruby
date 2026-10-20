# frozen_string_literal: true

ENV["RAILS_ENV"] = "test"
ENV["DATABASE_URL"] ||= "sqlite3::memory:"

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../sqrl-core/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../sqrl-rack/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../../sqrl-rails/lib", __dir__)

require "bundler/setup"
require_relative "dummy/config/application"
Rails.application.initialize!

require "rack/test"
require "erb"

# Schema: Devise's users table plus the sqrl-rails migration (through its generator
# template, exactly as `devise:sqrl:install` copies it).
module DummySchema
  TEMPLATE = File.expand_path("../../sqrl-rails/lib/generators/sqrl/install/templates/create_sqrl_tables.rb.tt", __dir__)

  def self.migration_version
    "[#{ActiveRecord::VERSION::STRING.to_f}]"
  end

  def self.load!
    ActiveRecord::Migration.verbose = false
    ActiveRecord::Schema.define do
      create_table :users, force: true do |t|
        t.string :email, null: false, default: ""
        t.string :encrypted_password, null: false, default: ""
        t.datetime :remember_created_at
        t.integer :sign_in_count, default: 0, null: false
        t.datetime :current_sign_in_at
        t.datetime :last_sign_in_at
        t.string :current_sign_in_ip
        t.string :last_sign_in_ip
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
    Devise::SQRL.reset!
    %w[sqrl_identities sqrl_nuts sqrl_pending_logins users].each do |table|
      ActiveRecord::Base.connection.execute("DELETE FROM #{table}")
    end
    Devise.sqrl_on_unknown_identity = nil
    Devise.sqrl_create_resource = nil
    Devise.sqrl_remember_me = false
    Devise.sqrl_login_block = {}
    Devise.sqrl_failure_path = nil
    cfg = SQRL::Rails.config
    cfg.host = nil
    cfg.scheme = nil
    cfg.on_unknown_identity = :create
    cfg.stores = :active_record
    cfg.require_ip_match = true
    cfg.ask = nil
    cfg.sin = nil
    cfg.nut_ttl = 300
    cfg.cps_token_ttl = 60
    cfg.clock = nil
  end
end
