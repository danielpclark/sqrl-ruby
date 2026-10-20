# frozen_string_literal: true

require "socket"
require "net/http"
require "timeout"
require "open3"
require "rbconfig"
require "openssl"
require "tmpdir"
require "fileutils"

# Boots one of the example applications under examples/ as a separate process, with its own
# Gemfile, on a free 127.0.0.1 port, and tears it down afterwards. Used by the integration
# specs so that every framework is exercised as a real, independently bundled application.
#
# Every app is served over HTTPS with a self-signed certificate generated once per run, so
# the login pages carry real `sqrl://` URLs (which always mean HTTPS) and the bot client
# verifies TLS against {ExampleApp.ca_file} exactly as it would against a public CA.
class ExampleApp
  ROOT = File.expand_path("../../examples", __dir__)

  # name:      directory under examples/
  # command:   argv to start the server; %PORT%, %KEY% and %CERT% are substituted
  # ready_path: path that must answer before the app counts as up
  Definition = Struct.new(:name, :command, :ready_path, :env, :setup, keyword_init: true)

  RACKUP_TLS = %w[bundle exec puma --bind ssl://127.0.0.1:%PORT%?key=%KEY%&cert=%CERT% config.ru].freeze
  RAILS_TLS = %w[bundle exec bin/rails server -b ssl://127.0.0.1:%PORT%?key=%KEY%&cert=%CERT% -e test].freeze

  DEFINITIONS = {
    "rack-app" => Definition.new(name: "rack-app", command: RACKUP_TLS, ready_path: "/"),
    "sinatra-app" => Definition.new(name: "sinatra-app", command: RACKUP_TLS, ready_path: "/"),
    "omniauth-app" => Definition.new(name: "omniauth-app", command: RACKUP_TLS, ready_path: "/"),
    "roda-app" => Definition.new(name: "roda-app", command: RACKUP_TLS, ready_path: "/"),
    "rails-auth-app" => Definition.new(
      name: "rails-auth-app",
      command: RAILS_TLS,
      ready_path: "/",
      env: { "RAILS_ENV" => "test" },
      setup: %w[bundle exec bin/rails db:prepare]
    ),
    "devise-app" => Definition.new(
      name: "devise-app",
      command: RAILS_TLS,
      ready_path: "/",
      env: { "RAILS_ENV" => "test" },
      setup: %w[bundle exec bin/rails db:prepare]
    )
  }.freeze

  TLS_MUTEX = Mutex.new

  # Paths of the self-signed key and certificate shared by every example app in this run
  # (CN and subjectAltName 127.0.0.1 / localhost, valid for one day). Generated lazily, once.
  #
  # @return [Hash{Symbol => String}] +:key+ and +:cert+ file paths
  def self.tls
    TLS_MUTEX.synchronize do
      @tls ||= begin
        dir = Dir.mktmpdir("sqrl-example-tls")
        at_exit { FileUtils.rm_rf(dir) }
        key = OpenSSL::PKey::RSA.new(2048)
        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = OpenSSL::BN.rand(64)
        cert.subject = OpenSSL::X509::Name.parse("/CN=127.0.0.1")
        cert.issuer = cert.subject
        cert.public_key = key.public_key
        cert.not_before = Time.now - 60
        cert.not_after = Time.now + 86_400
        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = cert
        ef.issuer_certificate = cert
        cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
        cert.add_extension(ef.create_extension("keyUsage", "digitalSignature,keyEncipherment,keyCertSign", true))
        cert.add_extension(ef.create_extension("subjectAltName", "IP:127.0.0.1,DNS:localhost"))
        cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash"))
        cert.sign(key, OpenSSL::Digest.new("SHA256"))
        key_file = File.join(dir, "key.pem")
        cert_file = File.join(dir, "cert.pem")
        File.write(key_file, key.to_pem)
        File.write(cert_file, cert.to_pem)
        File.chmod(0o600, key_file)
        { key: key_file, cert: cert_file }
      end
    end
  end

  # The certificate file a TLS client should trust for the example apps.
  def self.ca_file = tls[:cert]

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
    "https://127.0.0.1:#{@port}"
  end

  def url(path = "/")
    base_url + path
  end

  # The app's whole environment (spawned with +unsetenv_others+): the one this process had
  # before Bundler touched it (`bundle exec` points GEM_HOME / GEM_PATH at this repository's
  # bundle, which has none of the app's own gems), minus anything Bundler-specific, plus the
  # app's Gemfile and run settings.
  def environment
    base = defined?(Bundler) ? Bundler.original_env : ENV.to_h
    base = base.reject { |k, _| k.start_with?("BUNDLE_") || k == "RUBYOPT" }
    bindir = RbConfig::CONFIG["bindir"]
    path = [bindir, base["PATH"]].compact.join(File::PATH_SEPARATOR)
    base.merge(
      "PATH" => path,
      "PORT" => @port.to_s,
      "SQRL_HOST" => "127.0.0.1:#{@port}",
      "BUNDLE_GEMFILE" => File.join(dir, "Gemfile"),
      "RAILS_LOG_TO_STDOUT" => "1",
      "SECRET_KEY_BASE" => "integration-test-secret-key-base-not-for-production-#{@port}"
    ).merge(@definition.env || {}).merge(@extra_env)
  end

  def start
    run_setup
    tls = self.class.tls
    command = @definition.command.map do |c|
      c.sub("%PORT%", @port.to_s).sub("%KEY%", tls[:key]).sub("%CERT%", tls[:cert])
    end
    @stdin, @stdout, @wait = Open3.popen2e(environment, *command, chdir: dir, pgroup: true, unsetenv_others: true)
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

    out, status = Open3.capture2e(environment, *@definition.setup, chdir: dir, unsetenv_others: true)
    raise "setup for #{@name} failed:\n#{out}" unless status.success?
  end

  def wait_until_ready
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @boot_timeout
    loop do
      raise "#{@name} exited during boot:\n#{@log}" unless running?

      begin
        # Readiness only: the real clients verify the certificate against ExampleApp.ca_file.
        response = Net::HTTP.start("127.0.0.1", @port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE,
                                                       open_timeout: 1, read_timeout: 5) do |http|
          http.get(@definition.ready_path)
        end
        return if response.code.to_i < 500
      rescue SystemCallError, Net::OpenTimeout, Net::ReadTimeout, IOError, OpenSSL::SSL::SSLError
        nil
      end
      raise "#{@name} did not become ready on port #{@port} within #{@boot_timeout}s:\n#{@log}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.25
    end
  end
end
