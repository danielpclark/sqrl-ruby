# frozen_string_literal: true

RSpec.describe "plain http is opt-in" do
  it "Transport refuses plain http by default, even for loopback" do
    transport = SQRL::Client::Transport.new
    expect { transport.get("http://127.0.0.1:1/") }.to raise_error(SQRL::Client::TransportError, /plain http/)
    expect { SQRL::Client::Transport.new(allow_http: :loopback).get("http://127.0.0.1:1/") }
      .to raise_error(SQRL::Client::TransportError) { |e| expect(e.message).not_to match(/plain http is not allowed/) }
  end

  it "Agent refuses a plain-http login page and a qrl:// URL unless insecure: true" do
    site = start_site
    secure_agent = SQRL::Client::Agent.new(identity: SQRL::Client::Identity.ephemeral("secure"))
    expect(secure_agent).not_to be_insecure
    expect { secure_agent.login(site.login_url) }.to raise_error(SQRL::Client::TransportError, /plain http/)

    page = SQRL::Client::Transport.new(allow_http: :loopback).get(site.login_url)
    sqrl_url = SQRL::Client::Discovery.find(page.body, base_url: site.login_url).sqrl_url
    expect(sqrl_url).to start_with("qrl://")
    expect { secure_agent.login(sqrl_url) }.to raise_error(SQRL::Error, /insecure|plain http/)

    insecure_agent = SQRL::Client::Agent.new(identity: SQRL::Client::Identity.ephemeral("insecure"), insecure: true)
    expect(insecure_agent.login(site.login_url)).to be_authenticated
  end
end
