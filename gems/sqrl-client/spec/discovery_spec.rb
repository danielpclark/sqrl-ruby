# frozen_string_literal: true

RSpec.describe SQRL::Client::Discovery do
  let(:url) { "sqrl://example.com/sqrl/cli?nut=abc123&can=L2xvZ2lu" }

  it "prefers the data-sqrl-url attribute and resolves the status URL" do
    html = <<~HTML
      <div data-sqrl-login data-sqrl-url="#{url.sub("&", "&amp;")}" data-sqrl-status="/sqrl/status">
        <a data-sqrl-link href="#{url.sub("&", "&amp;")}">Sign in</a>
      </div>
    HTML
    r = described_class.find(html, base_url: "https://example.com/login")
    expect(r.sqrl_url).to eq(url)
    expect(r.status_url).to eq("https://example.com/sqrl/status")
    expect(r.source).to eq("data-sqrl-url")
  end

  it "finds a[data-sqrl-link], plain hrefs, CPS links and bare text URLs" do
    expect(described_class.find(%(<a data-sqrl-link href='#{url}'>x</a>)).source).to eq("a[data-sqrl-link]")
    expect(described_class.find(%(<p><a class="btn" href="#{url}">Sign in with SQRL</a></p>)).sqrl_url).to eq(url)
    cps = "http://localhost:25519/#{SQRL::Util.b64u_encode(url)}"
    r = described_class.find(%(<a href="/other">o</a><a href="#{cps}">Sign in</a>))
    expect(r.sqrl_url).to eq(url)
    expect(described_class.find("<html><body>Scan or click: #{url} today</body></html>").source).to eq("text")
    expect(described_class.find("<code>qrl://localhost:8080/cli.sqrl?nut=n</code>").sqrl_url).to eq("qrl://localhost:8080/cli.sqrl?nut=n")
  end

  it "ignores invalid candidates and raises when nothing is found" do
    html = %(<a href="qrl://example.com/not-loopback?nut=1">bad</a><a href="http://localhost:25519/%%%">bad</a><a href="#{url}">ok</a>)
    expect(described_class.find(html).sqrl_url).to eq(url)
    expect { described_class.find("<html><body>nothing here</body></html>", base_url: "https://x/login") }
      .to raise_error(SQRL::Client::DiscoveryError, %r{no sqrl:// login link found on https://x/login})
  end

  it "accepts a target that is itself a link" do
    expect(described_class.from_target(url).sqrl_url).to eq(url)
    expect(described_class.from_target("http://localhost:25519/#{SQRL::Util.b64u_encode(url)}").sqrl_url).to eq(url)
    expect(described_class.from_target("https://example.com/login")).to be_nil
    expect(described_class.find(url).source).to eq("target")
  end
end
