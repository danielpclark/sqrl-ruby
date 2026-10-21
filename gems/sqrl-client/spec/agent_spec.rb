# frozen_string_literal: true

RSpec.describe SQRL::Client::Agent do
  let(:site) { start_site }

  it "creates an account on first login and logs in with CPS" do
    id = ephemeral("alice")
    agent = new_agent(id)
    result = agent.login(site.login_url)
    expect(result).to be_authenticated
    expect(result).to be_created
    expect(result).not_to be_rekeyed
    expect(result.cps_url).to start_with("#{site.base_url}/sqrl/callback?t=")
    expect(result.landing.status).to eq(200)
    expect(result.landing.final_url).to eq("#{site.base_url}/welcome")
    expect(result.landing.body).to include(result.idk)
    expect(result.tif_history.map(&:to_hex)).to eq(%w[4 5])
    expect(result.transcript.map { |t| t[:command] }).to eq(%i[query ident])
    expect(result.transcript.first[:client_text]).not_to include("ids=")
    expect(site.identity_count).to eq(1)
    expect(result.cancel_url).to eq("#{site.base_url}/cancelled")

    # the cookie jar now carries the logged-in session
    expect(agent.http.get("#{site.base_url}/welcome").status).to eq(200)

    again = new_agent(id).login(site.login_url)
    expect(again).to be_authenticated
    expect(again).not_to be_created
    expect(again.idk).to eq(result.idk)
  end

  it "logs in without CPS by polling the status URL" do
    agent = new_agent(ephemeral("bob"), cps: false)
    result = agent.login(site.login_url)
    expect(result).to be_authenticated
    expect(result.cps_url).to be_nil
    expect(result.status).to include("authenticated" => true, "next" => "/welcome")
    expect(result.landing.status).to eq(200)
    expect(agent.http.get("#{site.base_url}/welcome").status).to eq(200)
  end

  it "accepts a sqrl:// URL or a localhost:25519 CPS link as the target" do
    page = SQRL::Client::Transport.new(allow_http: :loopback).get(site.login_url)
    url = page.body[/data-sqrl-url="([^"]+)"/, 1].gsub("&amp;", "&")
    agent = new_agent(ephemeral("carol"), poll: false)
    expect(agent.login(url)).to be_authenticated
    page2 = agent.http.get(site.login_url)
    url2 = page2.body[/data-sqrl-url="([^"]+)"/, 1].gsub("&amp;", "&")
    cps_link = "http://localhost:25519/#{SQRL::Util.b64u_encode(url2)}"
    expect(new_agent(ephemeral("carol")).login(cps_link)).to be_authenticated
  end

  it "queries without logging in" do
    id = ephemeral("dave")
    expect(new_agent(id).query(site.login_url).state).to eq(:unknown)
    new_agent(id).login(site.login_url)
    r = new_agent(id).query(site.login_url)
    expect(r.state).to eq(:known)
    expect(r).to be_known
    expect(r).not_to be_authenticated
    expect(site.identity_count).to eq(1)
  end

  it "refuses to create accounts when unknown_site is :refuse" do
    agent = new_agent(ephemeral, unknown_site: :refuse)
    expect { agent.login(site.login_url) }.to raise_error(SQRL::Client::LoginFailed) { |e| expect(e.reason).to eq(:unknown_site) }
    expect(site.identity_count).to eq(0)
  end

  it "disables, refuses login while disabled, enables with the IUK and removes" do
    id = ephemeral("erin")
    new_agent(id).login(site.login_url)
    d = new_agent(id).disable(site.login_url)
    expect(d.state).to be_disabled
    expect(d.tif).to be_sqrl_disabled
    expect { new_agent(id).login(site.login_url) }.to raise_error(SQRL::Client::LoginFailed) { |e| expect(e.reason).to eq(:disabled) }

    locked = SQRL::Client::Identity.new(id.unlocked)
    expect { new_agent(locked).enable(site.login_url) }.to raise_error(SQRL::Client::IdentityLocked)

    e = new_agent(id).enable(site.login_url)
    expect(e).to be_authenticated
    expect(e.landing.status).to eq(200)
    expect(new_agent(id).login(site.login_url)).to be_authenticated

    r = new_agent(id).remove(site.login_url)
    expect(r.tif).not_to be_id_match
    expect(site.identity_count).to eq(0)
    expect(new_agent(id).query(site.login_url).state).to eq(:unknown)
    expect(new_agent(id).login(site.login_url)).to be_created
  end

  it "re-keys the account when the identity was re-keyed and refuses the superseded one" do
    id = ephemeral("frank")
    first = new_agent(id).login(site.login_url)
    id.previous_identity || id
    id.rekey!
    expect(id.previous_count).to eq(1)
    result = new_agent(id).login(site.login_url)
    expect(result).to be_authenticated
    expect(result).to be_rekeyed
    expect(result.idk).not_to eq(first.idk)
    expect(result.transcript.last[:client_text]).to include("pidk=", "suk=", "vuk=")
    expect(site.identity_count).to eq(1)

    old = id.previous_identity
    expect { new_agent(old).login(site.login_url) }.to raise_error(SQRL::Client::LoginFailed) { |e| expect(e.reason).to eq(:superseded) }
    expect(new_agent(id).login(site.login_url)).not_to be_rekeyed
  end

  it "walks older previous identities in turn" do
    a = ephemeral("gina-1")
    new_agent(a).login(site.login_url)
    b = SQRL::Client::Identity.ephemeral(nil,
                                         previous: [SQRL::Util.random_bytes(32), SQRL::Util.random_bytes(32), a.iuk])
    result = new_agent(b).login(site.login_url)
    expect(result).to be_rekeyed
    expect(result.transcript.count { |t| t[:command] == :query }).to eq(3)
  end

  context "with an ask" do
    let(:site) do
      start_site(ask: SQRL::Ask.new(message: "Allow this login?", buttons: [{ label: "Allow" }, { label: "Deny" }]))
    end

    it "raises AskRequired without a handler and answers with one" do
      id = ephemeral("hank")
      new_agent(id).login(site.login_url) # creation: the ask is only posed for known identities
      expect { new_agent(id).login(site.login_url) }.to raise_error(SQRL::Client::AskRequired) { |e| expect(e.ask.message).to eq("Allow this login?") }
      seen = nil
      result = new_agent(id, ask_handler: lambda { |ask|
        seen = ask
        1
      }).login(site.login_url)
      expect(seen.buttons.map(&:label)).to eq(%w[Allow Deny])
      expect(result).to be_authenticated
      expect(result.ask).to eq(seen)
      expect(result.button).to eq(1)
      expect(result.transcript.last[:client_text]).to include("btn=1")
    end
  end

  context "with a secret index" do
    let(:site) { start_site(sin: "0") }

    it "sends ins and pins and logs in repeatedly" do
      id = ephemeral("ivy")
      r1 = new_agent(id).login(site.login_url)
      expect(r1.transcript.last[:client_text]).to include("ins=")
      expect(new_agent(id).login(site.login_url)).to be_authenticated
      id.rekey!
      r3 = new_agent(id).login(site.login_url)
      expect(r3).to be_rekeyed
      expect(r3.transcript.last[:client_text]).to include("pins=")
    end
  end

  it "retries a transient error once, then stops when the error repeats (stale login page)" do
    id = ephemeral("jack")
    page = SQRL::Client::Transport.new(allow_http: :loopback).get(site.login_url)
    url = page.body[/data-sqrl-url="([^"]+)"/, 1].gsub("&amp;", "&")
    stale = url.sub(/nut=[^&]+/, "nut=bogus")
    # The test site keeps its state by reference, so the retry fails exactly like the first
    # attempt; two identical TIFs mean the page has expired (Gibson, grc.sqrl:23543).
    expect { new_agent(id, poll: false, max_transient_retries: 5).login(stale) }
      .to raise_error(SQRL::Client::LoginFailed) do |e|
        expect(e.reason).to eq(:transient)
        expect(e.message).to include("refresh the page")
        expect(e.tif).to be_transient_error
      end
  end

  it "gives up after too many transient errors" do
    stale = "qrl://#{site.host}:#{site.port}/sqrl/cli?nut=bogus"
    broken = Class.new(SQRL::Client::Transport) do
      def post_form(url, body, headers = {}, **)
        # replay the very first request forever: its nut is unknown, so every answer is transient
        @first ||= [url, body]
        super(@first[0], @first[1], headers)
      end
    end.new(allow_http: :loopback)
    expect { new_agent(ephemeral, transport: broken, max_transient_retries: 1).login(stale) }
      .to raise_error(SQRL::Client::LoginFailed) { |e| expect(e.reason).to eq(:transient) }
  end

  it "uses a different identity per Alt-ID" do
    id = ephemeral("kim")
    a = new_agent(id).login(site.login_url)
    b = new_agent(id, alt_id: "work").login(site.login_url)
    expect(a).to be_created
    expect(b).to be_created
    expect(a.idk).not_to eq(b.idk)
    expect(site.identity_count).to eq(2)
  end

  it "reports discovery and transport failures" do
    expect { new_agent.login("#{site.base_url}/") }.to raise_error(SQRL::Client::DiscoveryError)
    expect { new_agent.login("#{site.base_url}/nope") }.to raise_error(SQRL::Client::TransportError) { |e| expect(e.status).to eq(404) }
    expect { new_agent.login("http://example.com/login") }.to raise_error(SQRL::Client::TransportError, /plain http/)
  end
end
