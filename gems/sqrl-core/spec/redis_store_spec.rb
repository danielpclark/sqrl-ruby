# frozen_string_literal: true

require "set"
require "socket"
require "support/store_contract"
require "support/fake_redis"
require "sqrl/server/redis"

RSpec.describe SQRL::Server::Redis do
  describe "with the in-process Redis double" do
    let(:stores) { described_class.stores(redis: FakeRedis.new, namespace: "t") }

    it_behaves_like "a SQRL store set"

    it "falls back to a script when GETDEL is not available" do
      redis = FakeRedis.new
      def redis.getdel(_key)
        raise Class.new(StandardError) { def self.name = "Redis::CommandError" }, "ERR unknown command 'GETDEL'"
      end
      stores = described_class.stores(redis: redis, namespace: "t")
      stores.nuts.issue(nut: "n", pending_login_id: "p", expected_server: "s", ip: "1.1.1.1", bound_idk: nil,
                        expires_at: Time.now + 60)
      expect(stores.nuts.consume("n")&.pending_login_id).to eq("p")
      expect(stores.nuts.consume("n")).to be_nil
    end

    it "gives nuts and pending logins a TTL" do
      redis = FakeRedis.new
      stores = described_class.stores(redis: redis, namespace: "t")
      stores.nuts.issue(nut: "n", pending_login_id: "p", expected_server: "s", ip: "1.1.1.1", bound_idk: nil,
                        expires_at: Time.now + 0.05)
      stores.pending_logins.create("p", ip: "1.1.1.1", return_to: nil, expires_at: Time.now + 0.05)
      sleep 0.08
      expect(redis.get("t:nut:n")).to be_nil
      expect(redis.hgetall("t:pl:p")).to eq({})
    end
  end

  describe "against a real Redis server" do
    # REDIS_URL names a server to use; otherwise a throwaway redis-server is started on a
    # free port when the binary is available; otherwise the group is skipped.
    before(:all) do
      @client = nil
      begin
        require "redis"
      rescue LoadError
        skip "the redis gem is not installed"
      end
      url = ENV["REDIS_URL"]
      if url.nil? && (bin = `which redis-server 2>/dev/null`.strip) && !bin.empty?
        port = TCPServer.new("127.0.0.1", 0).then { |s| s.addr[1].tap { s.close } }
        @server_pid = spawn(bin, "--port", port.to_s, "--save", "", "--appendonly", "no", "--bind", "127.0.0.1",
                            out: File::NULL, err: File::NULL)
        url = "redis://127.0.0.1:#{port}/15"
        deadline = Time.now + 5
        begin
          @client = ::Redis.new(url: url, timeout: 0.5)
          @client.ping
        rescue StandardError
          @client = nil
          retry if Time.now < deadline && sleep(0.1)
        end
      elsif url
        begin
          @client = ::Redis.new(url: url, timeout: 0.5)
          @client.ping
        rescue StandardError
          @client = nil
        end
      end
      skip "no Redis server reachable (set REDIS_URL or install redis-server)" unless @client
    end

    after(:all) do
      @client&.flushdb
      @client&.close
      if @server_pid
        Process.kill("TERM", @server_pid)
        Process.wait(@server_pid)
      end
    end

    before { @client.flushdb }

    let(:stores) { described_class.stores(redis: @client, namespace: "sqrl-spec") }

    it_behaves_like "a SQRL store set"

    it "reports the server's GETDEL support path" do
      stores.nuts.issue(nut: "n", pending_login_id: "p", expected_server: "s", ip: "1.1.1.1", bound_idk: nil,
                        expires_at: Time.now + 60)
      expect(@client.pttl("sqrl-spec:nut:n")).to be_between(1, 60_000)
      expect(stores.nuts.consume("n")&.pending_login_id).to eq("p")
    end
  end
end
