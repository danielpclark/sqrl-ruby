# frozen_string_literal: true

require "socket"
require "net/http"
require "timeout"
require "open3"
require "rbconfig"

# Boots one of the example applications under examples/ as a separate process, with its own
# Gemfile, on a free 127.0.0.1 port, and tears it down afterwards. Used by the integration
# specs so that every framework is exercised as a real, independently bundled application.
class ExampleApp
  ROOT = File.expand_path("../../examples", __dir__)

  # name:      directory under examples/
  # command:   argv to start the server; "%PORT%" is substituted
  # ready_path: path that must answer 200 before the app counts as up
  Definition = Struct.new(:name, :command, :ready_path, :env, :setup, keyword_init: true)

  DEFINITIONS = {
    "rack-app" => Definition.new(
      name: "rack-app",
      command: %w[bundle exec rackup --host 127.0.0.1 --port %PORT% config.ru],
      ready_path: "/"
    ),
    "sinatra-app" => Definition.new(
      name: "sinatra-app",
      command: %w[bundle exec rackup --host 127.0.0.1 --port %PORT% config.ru],
      ready_path: "/"
    ),
    "omniauth-app" => Definition.new(
      name: "omniauth-app",
      command: %w[bundle exec rackup --host 127.0.0.1 --port %PORT% config.ru],
      ready_path: "/"
    ),
    "roda-app" => Definition.new(
      name: "roda-app",
      command: %w[bundle exec rackup --host 127.0.0.1 --port %PORT% config.ru],
      ready_path: "/"
    ),
    "rails-auth-app" => Definition.new(
      name: "rails-auth-app",
      command: %w[bundle exec bin/rails server -b 127.0.0.1 -p %PORT% -e test],
      ready_path: "/",
      env: { "RAILS_ENV" => "test" },
      setup: %w[bundle exec bin/rails db:prepare]
    ),
    "devise-app" => Definition.new(
      name: "devise-app",
      command: %w[bundle exec bin/rails server -b 127.0.0.1 -p %PORT% -e test],
      ready_path: "/",
      env: { "RAILS_ENV" => "test" },
      setup: %w[bundle exec bin/rails db:prepare]
    )
  }.freeze

  attr_reader :name, :port, :log

  def self.free_port
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    server.close
    port
  end

  def self.start(name, **opts)
    app = new(name, **opts)
    app.start
    app
  end

  def initialize(name, env: {}, boot_timeout: 90)
    @definition = DEFINITIONS.fetch(name) { raise ArgumentError, "unknown example app #{name.inspect}" }
    @name = name
    @extra_env = env
    @boot_timeout = boot_timeout
    @port = self.class.free_port
    @log = +""
  end

  def dir
    File.join(ROOT, @name)
  end

  def base_url
    "http://127.0.0.1:#{@port}"
  end

  def url(path = "/")
    base_url + path
  end

  def environment
    base = ENV.to_h.reject { |k, _| k.start_with?("BUNDLE_") || k == "RUBYOPT" }
    bindir = RbConfig::CONFIG["bindir"]
    path = [bindir, base["PATH"]].compact.join(File::PATH_SEPARATOR)
    base.merge(
      "PATH" => path,
      "PORT" => @port.to_s,
      "SQRL_HOST" => "127.0.0.1:#{@port}",
      "SQRL_SCHEME" => "qrl",
      "BUNDLE_GEMFILE" => File.join(dir, "Gemfile"),
      "RAILS_LOG_TO_STDOUT" => "1",
      "SECRET_KEY_BASE" => "integration-test-secret-key-base-not-for-production-#{@port}"
    ).merge(@definition.env || {}).merge(@extra_env)
  end

  def start
    run_setup
    command = @definition.command.map { |c| c.sub("%PORT%", @port.to_s) }
    @stdin, @stdout, @wait = Open3.popen2e(environment, *command, chdir: dir, pgroup: true)
    @reader = Thread.new do
      @stdout.each_line { |line| @log << line }
    rescue IOError
      nil
    end
    wait_until_ready
    self
  end

  def stop
    return unless @wait

    begin
      Process.kill("TERM", -@wait.pid)
    rescue Errno::ESRCH, Errno::EPERM
      nil
    end
    begin
      Timeout.timeout(15) { @wait.value }
    rescue Timeout::Error
      begin
        Process.kill("KILL", -@wait.pid)
      rescue Errno::ESRCH
        nil
      end
    end
    @stdin&.close
    @reader&.join(2)
    @wait = nil
  end

  def running?
    @wait&.alive?
  end

  private

  def run_setup
    return unless @definition.setup

    out, status = Open3.capture2e(environment, *@definition.setup, chdir: dir)
    raise "setup for #{@name} failed:\n#{out}" unless status.success?
  end

  def wait_until_ready
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @boot_timeout
    loop do
      raise "#{@name} exited during boot:\n#{@log}" unless running?

      begin
        response = Net::HTTP.start("127.0.0.1", @port, open_timeout: 1, read_timeout: 5) do |http|
          http.get(@definition.ready_path)
        end
        return if response.code.to_i < 500
      rescue SystemCallError, Net::OpenTimeout, Net::ReadTimeout, IOError
        nil
      end
      raise "#{@name} did not become ready on port #{@port} within #{@boot_timeout}s:\n#{@log}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.25
    end
  end
end
