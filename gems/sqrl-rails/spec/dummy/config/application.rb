# frozen_string_literal: true

require "rails"
require "active_record/railtie"
require "action_controller/railtie"
require "action_view/railtie"
require "sqrl/rails"

module Dummy
  # Minimal host application: Rails 8's generated authentication stack (a copy of the
  # Authentication concern, Session and Current models) plus the SQRL engine.
  class Application < Rails::Application
    config.root = File.expand_path("..", __dir__)
    config.load_defaults Rails::VERSION::STRING.to_f
    config.eager_load = false
    config.secret_key_base = "dummy-secret-key-base-" * 3
    config.hosts.clear
    config.logger = Logger.new(File::NULL)
    config.active_support.deprecation = :stderr
    config.action_dispatch.show_exceptions = :none
    config.consider_all_requests_local = true
    config.session_store :cookie_store, key: "_dummy_session"
    config.active_record.maintain_test_schema = false if config.respond_to?(:active_record)
    config.paths["log"] = File.join(config.root, "log", "test.log")
  end
end
