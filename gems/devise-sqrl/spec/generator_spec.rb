# frozen_string_literal: true

require "tmpdir"
require "fileutils"
require "generators/devise/sqrl/install/install_generator"

RSpec.describe Devise::SQRL::Generators::InstallGenerator do
  def skeleton(dir)
    FileUtils.mkdir_p(File.join(dir, "app/models"))
    FileUtils.mkdir_p(File.join(dir, "app/views/devise/sessions"))
    FileUtils.mkdir_p(File.join(dir, "config/initializers"))
    FileUtils.mkdir_p(File.join(dir, "db/migrate"))
    File.write(File.join(dir, "app/models/user.rb"),
               "class User < ApplicationRecord\n  devise :database_authenticatable, :registerable,\n         " \
               ":recoverable, :rememberable, :validatable\nend\n")
    File.write(File.join(dir, "app/views/devise/sessions/new.html.erb"), "<h2>Log in</h2>\n")
  end

  def run(dir, *args)
    described_class.start(args, destination_root: dir, shell: Thor::Shell::Basic.new)
  end

  def capture
    old = $stdout
    $stdout = StringIO.new
    yield
    $stdout.string
  ensure
    $stdout = old
  end

  it "has the devise:sqrl:install namespace" do
    expect(described_class.namespace).to eq("devise:sqrl:install")
  end

  it "installs everything and is idempotent" do
    Dir.mktmpdir do |dir|
      skeleton(dir)
      out = capture { run(dir, "--host=example.com") }
      expect(out).to include("bin/rails db:migrate")

      migrations = Dir[File.join(dir, "db/migrate/*_create_sqrl_tables.rb")]
      expect(migrations.size).to eq(1)
      expect(File.read(migrations.first)).to include("create_table :sqrl_identities")

      user = File.read(File.join(dir, "app/models/user.rb"))
      expect(user).to include("devise :sqrl_authenticatable, :database_authenticatable, :registerable,")

      initializer = File.read(File.join(dir, "config/initializers/devise_sqrl.rb"))
      expect(initializer).to include('sqrl.host = "example.com"')
      expect(initializer).to include("config.sqrl_on_unknown_identity = :create")

      view = File.read(File.join(dir, "app/views/devise/sessions/new.html.erb"))
      expect(view).to include('render "devise/shared/sqrl", resource_name: resource_name')

      capture { run(dir, "--host=example.com") }
      expect(Dir[File.join(dir, "db/migrate/*_create_sqrl_tables.rb")].size).to eq(1)
      expect(File.read(File.join(dir, "app/models/user.rb")).scan("sqrl_authenticatable").size).to eq(1)
      expect(File.read(File.join(dir, "app/views/devise/sessions/new.html.erb")).scan("devise/shared/sqrl").size).to eq(1)
    end
  end

  it "accepts another model name and falls back to SQRL_HOST" do
    Dir.mktmpdir do |dir|
      skeleton(dir)
      FileUtils.mkdir_p(File.join(dir, "app/models"))
      File.write(File.join(dir, "app/models/admin.rb"), "class Admin < ApplicationRecord\n  devise :database_authenticatable\nend\n")
      capture { run(dir, "Admin", "--skip-views", "--skip-migration") }
      expect(File.read(File.join(dir, "app/models/admin.rb"))).to include("devise :sqrl_authenticatable, :database_authenticatable")
      expect(File.read(File.join(dir, "config/initializers/devise_sqrl.rb"))).to include('sqrl.host = ENV["SQRL_HOST"].presence')
      expect(Dir[File.join(dir, "db/migrate/*")]).to be_empty
    end
  end
end
