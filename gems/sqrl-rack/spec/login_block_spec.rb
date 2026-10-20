# frozen_string_literal: true

RSpec.describe SQRL::Rack::LoginBlock do
  let(:url) { "sqrl://example.com/sqrl/cli?nut=abc" }

  it "renders the markup contract sqrl.js expects" do
    html = described_class.render(login_url: url, status_url: "/sqrl/status", cancel_url: "/cancel",
                                  script_url: "/sqrl/sqrl.js", poll_ms: 1500)
    expect(html).to include('data-sqrl-login', %(data-sqrl-url="#{url}"), 'data-sqrl-status="/sqrl/status"',
                            'data-sqrl-poll="1500"', 'data-sqrl-link href="sqrl://example.com/sqrl/cli?nut=abc"',
                            "data-sqrl-message", 'aria-live="polite"', "<svg", 'href="/cancel"',
                            '<script src="/sqrl/sqrl.js" defer></script>')
    expect(html).to include(described_class::DEFAULT_TEXTS[:message])
  end

  it "escapes everything it interpolates" do
    html = described_class.render(login_url: "sqrl://example.com/?nut=<x>&a=\"b\"", status_url: "/s?<",
                                  link_text: "<b>", cancel_url: "/c?<", cancel_text: "<i>", qr: false,
                                  texts: { message: "<m>" }, extra_attrs: { "data-x" => "<y>" })
    expect(html).not_to include("<x>", "<b>", "<i>", "<m>", "<y>", '"b"')
    expect(html).to include("&lt;x&gt;", "&lt;b&gt;", "&lt;m&gt;", "&quot;b&quot;", 'data-x="&lt;y&gt;"')
  end

  it "can omit the QR code, cancel link and script" do
    html = described_class.render(login_url: url, status_url: "/s", qr: false)
    expect(html).not_to include("<svg", "__cancel", "<script")
  end

  it "accepts a LoginURL" do
    login = SQRL::Server::LoginURL.new(url: url, nut: "abc", pending_login_id: "p")
    expect(described_class.render(login_url: login, status_url: "/s", qr: false)).to include(%(href="#{url}"))
  end

  it "inlines the script when no src is given" do
    expect(described_class.script_tag).to include("<script>", "data-sqrl-login", "localhost:25519")
  end
end

RSpec.describe SQRL::Rack::QR do
  it "renders an accessible SVG with a path for the dark modules" do
    svg = described_class.svg("sqrl://example.com/sqrl/cli?nut=abc", title: "Scan <me>")
    expect(svg).to start_with("<svg")
    expect(svg).to include('role="img"', 'aria-label="Scan &lt;me&gt;"', "<title>Scan &lt;me&gt;</title>",
                           'width="256"', "<path d=\"M4 4h1v1h-1z")
  end

  it "sizes by module when asked" do
    svg = described_class.svg("sqrl://example.com/", module_size: 4, quiet_zone: 2)
    count = svg[/viewBox="0 0 (\d+)/, 1].to_i
    expect(svg).to include(%(width="#{count * 4}"))
  end

  it "renders PNG bytes" do
    expect(described_class.png("sqrl://example.com/")).to start_with("\x89PNG".b)
  end
end

RSpec.describe SQRL::Rack::Assets do
  it "exposes the script and a digest" do
    expect(File).to exist(described_class.javascript_path)
    expect(described_class.javascript).to include("data-sqrl-login")
    expect(described_class.javascript_digest).to match(/\A[0-9a-f]{16}\z/)
  end
end
