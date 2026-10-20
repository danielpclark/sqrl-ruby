# frozen_string_literal: true

require "sqrl/client/cli"
require "tmpdir"
require "open3"

RSpec.describe SQRL::Client::CLI do
  let(:site) { start_site }

  def run_cli(*argv, env: {})
    out = StringIO.new
    err = StringIO.new
    code = nil
    with_env(env) { code = described_class.new(out: out, err: err).run(argv) }
    [code, out.string, err.string]
  end

  def with_env(env)
    saved = env.keys.to_h { |k| [k, ENV.fetch(k, nil)] }
    env.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    yield
  ensure
    saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end

  let(:iuk_hex) { "ab" * 32 }

  it "prints usage and version" do
    expect(run_cli).to match([3, /Usage/, ""])
    expect(run_cli("help")).to match([0, /Usage/, ""])
    expect(run_cli("version")).to match([0, /sqrl-client #{SQRL::VERSION}/, ""])
    expect(run_cli("bogus")).to match([3, "", /unknown command/])
    expect(run_cli("login")).to match([3, "", /needs a URL/])
  end

  it "logs in with an ephemeral identity, writes cookies and emits JSON" do
    Dir.mktmpdir do |dir|
      jar = File.join(dir, "cookies.txt")
      code, out, err = run_cli("login", site.login_url, "--iuk-hex", iuk_hex, "--cookies-out", jar)
      expect(err).to eq("")
      expect(code).to eq(0)
      expect(out).to include("ident: known", "authenticated: true (account created)", "landing: HTTP 200")
      expect(File.read(jar)).to include("\tuser\t")

      code, out, = run_cli("login", site.login_url, "--json", "--no-cps", env: { "SQRL_IUK_HEX" => iuk_hex })
      expect(code).to eq(0)
      data = JSON.parse(out)
      expect(data).to include("command" => "ident", "authenticated" => true, "created" => false)

      code, out, = run_cli("query", site.login_url, "--iuk-hex", iuk_hex)
      expect(code).to eq(0)
      expect(out).to include("query: known")

      jar_json = File.join(dir, "cookies.json")
      code, = run_cli("disable", site.login_url, "--iuk-hex", iuk_hex, "--cookies-out", jar_json, "--cookies-format", "json")
      expect(code).to eq(0)
      expect(JSON.parse(File.read(jar_json))).to be_an(Array)
      code, _, err = run_cli("login", site.login_url, "--iuk-hex", iuk_hex)
      expect(code).to eq(1)
      expect(err).to include("disabled")
      expect(run_cli("enable", site.login_url, "--iuk-hex", iuk_hex).first).to eq(0)
      expect(run_cli("remove", site.login_url, "--iuk-hex", iuk_hex).first).to eq(0)
      expect(site.identity_count).to eq(0)
    end
  end

  it "maps failures to exit codes" do
    expect(run_cli("login", site.login_url, "--iuk-hex", iuk_hex, "--refuse-unknown").first).to eq(1)
    expect(run_cli("login", "http://127.0.0.1:1/login", "--iuk-hex", iuk_hex).first).to eq(2)
    expect(run_cli("login", site.login_url).first).to eq(3) # no identity
  end

  it "creates, shows and uses a file identity" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "bot.sqrl")
      code, out, = run_cli("identity", "create", "--out", path, "--password", "pw", "--pw-seconds", "1", "--rescue-seconds", "0.001", "--json")
      expect(code).to eq(0)
      info = JSON.parse(out)
      expect(info["rescue_code"]).to match(/\A\d{4}(-\d{4}){5}\z/)
      expect(run_cli("identity", "show", "--identity", path, "--password", "pw")).to match([0, /fingerprint: #{info['fingerprint']}/, ""])
      code, out, = run_cli("login", site.login_url, "--identity", path, "--password", "pw")
      expect(code).to eq(0)
      expect(out).to include("authenticated: true")
      # enable needs the rescue code for a file identity
      run_cli("disable", site.login_url, "--identity", path, "--password", "pw")
      expect(run_cli("enable", site.login_url, "--identity", path, "--password", "pw").first).to eq(1)
      expect(run_cli("enable", site.login_url, "--identity", path, "--password", "pw", "--rescue-code", info["rescue_code"]).first).to eq(0)
      expect(run_cli("identity", "create").first).to eq(3)
    end
  end

  it "exports, re-keys, changes the password and lists previous identities" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "bot.sqrl")
      code, out, = run_cli("identity", "create", "--out", path, "--password", "pw", "--pw-seconds", "1", "--rescue-seconds", "0.001", "--json")
      expect(code).to eq(0)
      created = JSON.parse(out)

      code, out, = run_cli("identity", "export", "--identity", path, "--password", "pw", "--format", "s4-text")
      expect(code).to eq(0)
      expect(out).to start_with("SQRLDATA")
      expect(run_cli("identity", "export", "--identity", path, "--password", "pw", "--format", "binary").first).to eq(3)
      bin = File.join(dir, "bot.bin")
      expect(run_cli("identity", "export", "--identity", path, "--password", "pw", "--format", "binary", "--out", bin).first).to eq(0)
      expect(File.binread(bin)).to start_with("sqrldata")
      textual = File.join(dir, "bot.txt")
      expect(run_cli("identity", "export", "--identity", path, "--password", "pw", "--format", "textual", "--out", textual).first).to eq(0)
      expect(File.read(textual)).to match(/\A[2-9A-Za-z ]+(\n[2-9A-Za-z ]+)*\n?\z/)
      imported = File.join(dir, "imported.sqrl")
      code, out, = run_cli("identity", "import", "--textual", textual, "--rescue-code", created["rescue_code"], "--out", imported, "--password", "pw2", "--json")
      expect(code).to eq(0)
      expect(JSON.parse(out)["fingerprint"]).to eq(created["fingerprint"])

      expect(run_cli("identity", "previous", "--identity", path, "--password", "pw")).to match([0, /previous: none/, ""])

      code, out, = run_cli("identity", "change-password", "--identity", path, "--password", "pw", "--new-password", "pw3", "--pw-seconds", "1")
      expect(code).to eq(0)
      expect(out).to include("Password changed")
      expect(run_cli("identity", "show", "--identity", path, "--password", "pw").first).to eq(1)
      expect(run_cli("identity", "show", "--identity", path, "--password", "pw3").first).to eq(0)

      first = run_cli("login", site.login_url, "--identity", path, "--password", "pw3")
      expect(first.first).to eq(0)

      expect(run_cli("identity", "rekey", "--identity", path, "--password", "pw3").first).to eq(3) # needs the rescue code
      code, out, = run_cli("identity", "rekey", "--identity", path, "--password", "pw3", "--rescue-code", created["rescue_code"], "--rescue-seconds", "0.001", "--json")
      expect(code).to eq(0)
      rekeyed = JSON.parse(out)
      expect(rekeyed["fingerprint"]).not_to eq(created["fingerprint"])
      expect(rekeyed["previous_identities"]).to eq(1)
      expect(rekeyed["rescue_code"]).to match(/\A\d{4}(-\d{4}){5}\z/)
      code, out, = run_cli("identity", "previous", "--identity", path, "--password", "pw3", "--json")
      expect(code).to eq(0)
      expect(JSON.parse(out)).to eq("current" => rekeyed["fingerprint"], "previous" => [{ "index" => 0, "fingerprint" => created["fingerprint"] }])

      code, out, = run_cli("login", site.login_url, "--identity", path, "--password", "pw3")
      expect(code).to eq(0)
      expect(out).to include("account re-keyed")
      # the old rescue code no longer unlocks the file
      expect(run_cli("identity", "rekey", "--identity", path, "--password", "pw3", "--rescue-code", created["rescue_code"], "--rescue-seconds", "0.001").first).to eq(1)
    end
  end

  it "runs the conformance suite and writes a JUnit report" do
    Dir.mktmpdir do |dir|
      report = File.join(dir, "junit.xml")
      code, out, = run_cli("conformance", site.login_url, "--only", "create_account,login_existing,nut_replay_rejected", "--report", report)
      expect(code).to eq(0)
      expect(out).to include("PASS  happy/create_account", "3 passed, 0 failed")
      expect(File.read(report)).to include('tests="3"')
    end
  end

  it "runs as an executable" do
    exe = File.expand_path("../exe/sqrl-client", __dir__)
    core = File.expand_path("../../sqrl-core/lib", __dir__)
    lib = File.expand_path("../lib", __dir__)
    out, err, status = Open3.capture3({ "SQRL_IUK_HEX" => iuk_hex }, RbConfig.ruby, "-I", core, "-I", lib, exe, "login", site.login_url, "--json")
    expect(err).to eq("")
    expect(status.exitstatus).to eq(0)
    expect(JSON.parse(out)["authenticated"]).to be(true)
  end
end
