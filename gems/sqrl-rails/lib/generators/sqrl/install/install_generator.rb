# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

# Generator namespace (+bin/rails generate sqrl:install+).
module Sqrl
  # Generator namespace.
  module Generators
    # `bin/rails generate sqrl:install`
    #
    # Adds the SQRL tables, mounts the engine, writes the initializer, links the user
    # model and, when the application has Rails 8's generated login form, drops the SQRL
    # login block into it. Every step is idempotent.
    class InstallGenerator < ::Rails::Generators::Base
      include ::ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      class_option :skip_migration, type: :boolean, default: false, desc: "Do not copy the migration"
      class_option :skip_views, type: :boolean, default: false, desc: "Do not touch app/views/sessions/new.html.erb"
      class_option :skip_routes, type: :boolean, default: false, desc: "Do not mount the engine"
      class_option :host, type: :string, default: nil, desc: "Public host for sqrl:// URLs (default: request host)"
      class_option :mount, type: :string, default: "/sqrl", desc: "Where to mount the engine"
      class_option :user_model, type: :string, default: "User", desc: "Name of the user model"

      # Copy the +create_sqrl_tables+ migration unless one exists.
      def copy_migration
        return if options[:skip_migration]

        migration_template "create_sqrl_tables.rb.tt", "db/migrate/create_sqrl_tables.rb"
      end

      # Mount the engine in +config/routes.rb+ (idempotent).
      def mount_engine
        return if options[:skip_routes]

        line = %(mount SQRL::Rails::Engine, at: "#{options[:mount]}", as: :sqrl)
        return say_status(:identical, "config/routes.rb already mounts the engine", :blue) if routes_include?(line)

        route line
      end

      # Write +config/initializers/sqrl.rb+ with every option documented.
      def create_initializer
        template "initializer.rb.tt", "config/initializers/sqrl.rb"
      end

      # Add +has_many :sqrl_identities+ to the user model (idempotent).
      def link_user_model
        path = user_model_path
        full = File.expand_path(path, destination_root)
        return say_status(:skip, "#{path} not found; add `has_many :sqrl_identities` yourself", :yellow) unless File.exist?(full)

        association = %(  has_many :sqrl_identities, class_name: "SQRL::Rails::Identity", as: :user, dependent: :destroy\n)
        if File.read(full).include?("has_many :sqrl_identities")
          say_status(:identical, path, :blue)
        else
          inject_into_class path, options[:user_model].classify, association
        end
      end

      # Enforce the sqrlonly / hardlock account policies in the controllers that
      # `bin/rails generate authentication` produced.
      def include_password_policy
        inject_policy("app/controllers/sessions_controller.rb", "SessionsController",
                      "SQRL::Rails::PasswordPolicy::Sessions")
        inject_policy("app/controllers/passwords_controller.rb", "PasswordsController",
                      "SQRL::Rails::PasswordPolicy::Passwords")
      end

      # Append the login block to +sessions/new+ when that view exists (idempotent).
      def add_login_block_to_sessions_view
        return if options[:skip_views]

        path = "app/views/sessions/new.html.erb"
        full = File.expand_path(path, destination_root)
        return unless File.exist?(full)

        if File.read(full).include?("sqrl_login_block")
          say_status(:identical, path, :blue)
        else
          append_to_file path, "\n<hr>\n<h2>Or sign in with SQRL</h2>\n<%= sqrl_login_block %>\n"
        end
      end

      # Print what to do next.
      def show_next_steps
        say <<~TEXT

          SQRL login is set up. Next:

            bin/rails db:migrate

          Then start the server and open /sessions/new (or #{options[:mount]}/login).
          Configuration lives in config/initializers/sqrl.rb.
        TEXT
      end

      private

      def inject_policy(path, klass, concern)
        full = File.expand_path(path, destination_root)
        return unless File.exist?(full)

        if File.read(full).include?(concern)
          say_status(:identical, path, :blue)
        else
          inject_into_class path, klass, "  include #{concern}\n"
        end
      end

      def user_model_path
        "app/models/#{options[:user_model].underscore}.rb"
      end

      def routes_include?(line)
        path = File.expand_path("config/routes.rb", destination_root)
        File.exist?(path) && File.read(path).include?(line)
      end

      def host_option
        options[:host]
      end

      def migration_version
        "[#{::ActiveRecord::Migration.current_version}]"
      end
    end
  end
end
