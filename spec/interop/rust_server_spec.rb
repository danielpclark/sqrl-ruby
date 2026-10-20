# frozen_string_literal: true

# Cross-implementation interoperability: the Ruby bot client against the Rust reference
# server from danielpclark/SQRL-extension (crates/sqrl-test-server).
#
#   cargo build --release -p sqrl-test-server      # in the SQRL-extension checkout
#   SQRL_RUST_TEST_SERVER=path/to/sqrl-test-server bundle exec rspec spec/interop -I spec
require "spec_helper"
require "socket"
require "sqrl/client"
require "sqrl/client/conformance"

module RustServer
  DEFAULT_BINARY = "/tmp/claude-0/-home-user/fe9a8836-0a81-5ae7-be8e-5ce4e1b7c999/scratchpad/rust-target/release/sqrl-test-server"

  def self.binary
    ENV.fetch("SQRL_RUST_TEST_SERVER", DEFAULT_BINARY)
  end

  def self.available?
    File.executable?(binary)
  end

  # Boots `sqrl-test-server 127.0.0.1:PORT` and waits for it to answer.
  class Instance
    attr_reader :port, :base_url

    def initialize(env = {})
      @port = TCPServer.open("127.0.0.1", 0) { |s| s.addr[1] }
      @base_url = "http://localhost:#{@port}"
      @pid = Process.spawn(env, RustServer.binary, "127.0.0.1:#{@port}", out: File::NULL, err: File::NULL)
      wait_ready
    end

    def stop
      Process.kill("TERM", @pid)
      Process.wait(@pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end

    private

    def wait_ready
      deadline = Time.now + 10
      begin
        TCPSocket.new("127.0.0.1", @port).close
      rescue Errno::ECONNREFUSED
        raise "sqrl-test-server did not start" if Time.now > deadline

        sleep 0.05
        retry
      end
    end
  end

  # The Rust test site's page is `GET /` with the qrl:// URL in a <code> element and a
  # `session=` id; its poll endpoint is /status?session=ID (not cookie-bound) and its CPS
  # landing /loggedin?session=ID.
  class Site < SQRL::Client::Conformance::Site
    def login_page(transport)
      response = transport.get(login_url)
      unless response.success?
        raise SQRL::Client::TransportError.new("page answered #{response.status}",
                                               url: login_url)
      end

      session = response.body[/session=([A-Za-z0-9_-]+)/, 1]
      found = SQRL::Client::Discovery.find(response.body, base_url: response.final_url)
      Page.new(sqrl_url: found.sqrl_url, status_url: "#{login_url.chomp("/")}/status?session=#{session}",
               page_url: response.final_url, html: response.body)
    end

    def success?(response, _page = nil)
      !response.nil? && response.success? && response.body.include?("Logged in")
    end
  end
end

RSpec.describe "Ruby client against the Rust reference server", :interop do
  before(:all) do
    skip "sqrl-test-server binary not found at #{RustServer.binary} (set SQRL_RUST_TEST_SERVER)" unless RustServer.available?
  end

  def runner_for(server, features: {}, only: nil)
    SQRL::Client::Conformance::Runner.new(
      login_url: "#{server.base_url}/", site: RustServer::Site.new(login_url: "#{server.base_url}/"),
      # The Rust test server keys its CPS landing by session id rather than a one-time token
      # and has no cookie-bound callback, so those two cases do not apply to it.
      features: { cps_single_use: false, concurrency: true }.merge(features), only: only
    )
  end

  it "passes the conformance suite (plain)" do
    server = RustServer::Instance.new
    begin
      report = runner_for(server).run
      expect(report.failed.map { |c| [c.name, c.message] }).to eq([])
      expect(report.passed.size).to be >= 15
      expect(report.passed.map(&:name)).to include(:alt_id_is_distinct, :rekey_moves_account, :remove_then_recreate)
    ensure
      server.stop
    end
  end

  it "handles ask/btn (SQRL_ASK=1)" do
    server = RustServer::Instance.new("SQRL_ASK" => "1")
    begin
      report = runner_for(server, features: { ask: true }, only: %i[ask_and_button create_account login_existing]).run
      expect(report.failed.map { |c| [c.name, c.message] }).to eq([])
    ensure
      server.stop
    end
  end

  it "handles sin/ins (SQRL_SIN=1)" do
    server = RustServer::Instance.new("SQRL_SIN" => "1")
    begin
      report = runner_for(server, features: { sin: true }, only: %i[sin_and_ins rekey_moves_account login_existing]).run
      expect(report.failed.map { |c| [c.name, c.message] }).to eq([])
    ensure
      server.stop
    end
  end

  it "logs in with the Agent and lands on the Rust server's logged-in page" do
    server = RustServer::Instance.new
    begin
      agent = SQRL::Client::Agent.new(identity: SQRL::Client::Identity.ephemeral("interop"))
      result = agent.login("#{server.base_url}/")
      expect(result).to be_authenticated
      expect(result).to be_created
      expect(result.cps_url).to start_with("#{server.base_url}/loggedin?session=")
      expect(result.landing.body).to include("Logged in", result.idk)
    ensure
      server.stop
    end
  end
end
