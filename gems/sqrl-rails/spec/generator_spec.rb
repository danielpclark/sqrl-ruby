# frozen_string_literal: true

require "tmpdir"
require "fileutils"
require "generators/sqrl/install/install_generator"

RSpec.describe Sqrl::Generators::InstallGenerator do
  def skeleton(dir)
    FileUtils.mkdir_p(File.join(dir, "app/models"))
    FileUtils.mkdir_p(File.join(dir, "app/views/sessions"))
    FileUtils.mkdir_p(File.join(dir, "config"))
    FileUtils.mkdir_p(File.join(dir, "db/migrate"))
    File.write(File.join(dir, "app/models/user.rb"), "class User < ApplicationRecord\n  has_secure_password\nend\n")
    File.write(File.join(dir, "config/routes.rb"), "Rails.application.routes.draw do\n  resource :session\nend\n")
    File.write(File.join(dir, "app/views/sessions/new.html.erb"), "<%= form_with url: session_path do |f| %><% end %>\n")
    FileUtils.mkdir_p(File.join(dir, "app/controllers"))
    File.write(File.join(dir, "app/controllers/sessions_controller.rb"),
               "class SessionsController < ApplicationController\n  def create\n  end\nend\n")
    File.write(File.join(dir, "app/controllers/passwords_controller.rb"),
               "class PasswordsController < ApplicationController\n  def create\n  end\nend\n")
  end

  def run(dir, *args)
    described_class.start(args, destination_root: dir, shell: Thor::Shell::Basic.new.tap { |s| s.mute {} })
  end

  it "installs everything and is idempotent" do
    Dir.mktmpdir do |dir|
      skeleton(dir)
      out = capture { run(dir, "--host=example.com") }
      expect(out).to include("bin/rails db:migrate")

      migrations = Dir[File.join(dir, "db/migrate/*_create_sqrl_tables.rb")]
      expect(migrations.size).to eq(1)
      migration = File.read(migrations.first)
      expect(migration).to include("create_table :sqrl_identities")
      expect(migration).to include("ActiveRecord::Migration[")

      routes = File.read(File.join(dir, "config/routes.rb"))
      expect(routes).to include('mount SQRL::Rails::Engine, at: "/sqrl", as: :sqrl')

      initializer = File.read(File.join(dir, "config/initializers/sqrl.rb"))
      expect(initializer).to include('sqrl.host = "example.com"')
      expect(initializer).to include('sqrl.user_class = "User"')

      user = File.read(File.join(dir, "app/models/user.rb"))
      expect(user).to include('has_many :sqrl_identities, class_name: "SQRL::Rails::Identity", as: :user')

      view = File.read(File.join(dir, "app/views/sessions/new.html.erb"))
      expect(view).to include("<%= sqrl_login_block %>")

      sessions = File.read(File.join(dir, "app/controllers/sessions_controller.rb"))
      expect(sessions).to include("include SQRL::Rails::PasswordPolicy::Sessions")
      passwords = File.read(File.join(dir, "app/controllers/passwords_controller.rb"))
      expect(passwords).to include("include SQRL::Rails::PasswordPolicy::Passwords")
      expect(initializer).to include("SQRL_ASK")

      capture { run(dir, "--host=example.com", "--skip-migration") }
      expect(Dir[File.join(dir, "db/migrate/*_create_sqrl_tables.rb")].size).to eq(1)
      expect(File.read(File.join(dir, "config/routes.rb")).scan("mount SQRL::Rails::Engine").size).to eq(1)
      expect(File.read(File.join(dir, "app/models/user.rb")).scan("has_many :sqrl_identities").size).to eq(1)
      expect(File.read(File.join(dir, "app/views/sessions/new.html.erb")).scan("sqrl_login_block").size).to eq(1)
      expect(File.read(File.join(dir, "app/controllers/sessions_controller.rb")).scan("PasswordPolicy").size).to eq(1)
    end
  end

  it "falls back to the SQRL_HOST environment variable when no host is given" do
    Dir.mktmpdir do |dir|
      skeleton(dir)
      capture { run(dir, "--skip-views", "--skip-routes") }
      initializer = File.read(File.join(dir, "config/initializers/sqrl.rb"))
      expect(initializer).to include('sqrl.host = ENV["SQRL_HOST"].presence')
      expect(File.read(File.join(dir, "config/routes.rb"))).not_to include("mount SQRL")
      expect(File.read(File.join(dir, "app/views/sessions/new.html.erb"))).not_to include("sqrl_login_block")
    end
  end

  def capture
    old = $stdout
    $stdout = StringIO.new
    yield
    $stdout.string
  ensure
    $stdout = old
  end
end
