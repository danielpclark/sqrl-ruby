# frozen_string_literal: true

require "rspec/core/rake_task"

GEMS = %w[sqrl-core sqrl-client sqrl-rack omniauth-sqrl sqrl-rails devise-sqrl].freeze

namespace :spec do
  GEMS.each do |gem_name|
    desc "Run the #{gem_name} specs"
    RSpec::Core::RakeTask.new(gem_name) do |t|
      t.pattern = "gems/#{gem_name}/spec/**/*_spec.rb"
      t.rspec_opts = "-I gems/#{gem_name}/lib -I gems/#{gem_name}/spec --default-path gems/#{gem_name}/spec"
    end
  end

  desc "Run the integration specs (boot every example app)"
  RSpec::Core::RakeTask.new(:integration) do |t|
    t.pattern = "spec/integration/**/*_spec.rb"
    t.rspec_opts = "-I spec --default-path spec"
  end

  desc "Run every gem's specs"
  task gems: GEMS.map { |g| "spec:#{g}" }
end

desc "Run every gem's specs followed by the integration specs"
task spec: ["spec:gems", "spec:integration"]

task default: "spec:gems"

desc "Build every gem into pkg/"
task :build do
  require "fileutils"
  require_relative "gems/sqrl-core/lib/sqrl/version"
  FileUtils.mkdir_p("pkg")
  GEMS.each do |gem_name|
    Dir.chdir("gems/#{gem_name}") do
      sh "gem build #{gem_name}.gemspec --output ../../pkg/#{gem_name}-#{SQRL::VERSION}.gem"
    end
  end
end
