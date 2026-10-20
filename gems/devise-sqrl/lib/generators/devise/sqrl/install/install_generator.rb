# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"
require "sqrl/rails"

module Devise
  module SQRL
    module Generators
      # `bin/rails generate devise:sqrl:install [MODEL]`
      #
      # Adds the SQRL tables (the sqrl-rails migration), declares +:sqrl_authenticatable+
      # on the Devise model, writes +config/initializers/devise_sqrl.rb+ and drops the
      # SQRL block into +devise/sessions/new.html.erb+ when the app has it. Idempotent.
      class InstallGenerator < ::Rails::Generators::Base
        include ::ActiveRecord::Generators::Migration

        # The migration is the sqrl-rails one, so both gems create identical tables.
        SQRL_RAILS_TEMPLATES = File.join(::SQRL::Rails::Engine.root, "lib/generators/sqrl/install/templates")

        source_root File.expand_path("templates", __dir__)
        source_paths << SQRL_RAILS_TEMPLATES

        argument :model_name, type: :string, default: "User", desc: "The Devise model"

        class_option :skip_migration, type: :boolean, default: false, desc: "Do not copy the migration"
        class_option :skip_views, type: :boolean, default: false,
                                  desc: "Do not touch app/views/devise/sessions/new.html.erb"
        class_option :host, type: :string, default: nil, desc: "Public host for sqrl:// URLs (default: request host)"

        def self.namespace(name = nil)
          name ? super : "devise:sqrl:install"
        end

        def copy_migration
          return if options[:skip_migration]
          if Dir[File.join(destination_root, "db/migrate/*_create_sqrl_tables.rb")].any?
            return say_status(:identical, "db/migrate/*_create_sqrl_tables.rb", :blue)
          end

          migration_template "create_sqrl_tables.rb.tt", "db/migrate/create_sqrl_tables.rb"
        end

        def add_module_to_model
          path = "app/models/#{model_name.underscore}.rb"
          full = File.expand_path(path, destination_root)
          unless File.exist?(full)
            return say_status(:skip, "#{path} not found; add :sqrl_authenticatable to its devise call", :yellow)
          end

          content = File.read(full)
          return say_status(:identical, path, :blue) if content.include?("sqrl_authenticatable")

          if content.match?(/^\s*devise\s+:/)
            inject_into_file path, ":sqrl_authenticatable, ", after: /^\s*devise\s+(?=:)/
          else
            inject_into_class path, model_name.classify, "  devise :sqrl_authenticatable\n"
          end
        end

        def create_initializer
          template "devise_sqrl.rb.tt", "config/initializers/devise_sqrl.rb"
        end

        def add_partial_to_sessions_view
          return if options[:skip_views]

          path = "app/views/devise/sessions/new.html.erb"
          full = File.expand_path(path, destination_root)
          unless File.exist?(full)
            return say_status(:skip, "#{path} not found (run `bin/rails g devise:views -v sessions`); " \
                                     "render \"devise/shared/sqrl\" in your sign-in page", :yellow)
          end

          if File.read(full).include?("devise/shared/sqrl")
            say_status(:identical, path, :blue)
          else
            append_to_file path, %(\n<%= render "devise/shared/sqrl", resource_name: resource_name %>\n)
          end
        end

        def show_next_steps
          say <<~TEXT

            SQRL login is set up for #{model_name.classify}. Next:

              bin/rails db:migrate

            Then open the sign-in page: the SQRL block (link, QR code) is rendered by the
            devise/shared/sqrl partial. Settings: config/initializers/devise_sqrl.rb.
          TEXT
        end

        private

        def host_option
          options[:host]
        end

        def migration_version
          "[#{::ActiveRecord::Migration.current_version}]"
        end
      end
    end
  end
end
