# frozen_string_literal: true

RSpec.describe SQRL::Client::Transport do
  let(:site) { start_site }

  it "keeps cookies across requests and follows redirects" do
    t = described_class.new
    page = t.get(site.login_url)
    expect(page.status).to eq(200)
    expect(t.cookies.map(&:name)).to include("pl")
    expect(t.get("#{site.base_url}/welcome").status).to eq(403)
    expect(t.get("#{site.base_url}/logout").final_url).to eq(site.login_url)
    expect(t.get("#{site.base_url}/logout", follow_redirects: false).status).to eq(303)
    expect(t.cookies_netscape).to include("# Netscape HTTP Cookie File", "\tpl\t")
    expect(t.cookies_as_hashes.first).to include(:name, :value, :domain, :path)
    t.clear_cookies!
    expect(t.cookies.to_a).to be_empty
  end

  it "refuses plain http outside loopback unless allowed, and reports connection errors" do
    expect { described_class.new.get("http://example.com/") }.to raise_error(SQRL::Client::TransportError, /plain http/)
    expect { described_class.new(allow_http: false).get(site.login_url) }.to raise_error(SQRL::Client::TransportError)
    expect { described_class.new.get("ftp://example.com/") }.to raise_error(SQRL::Client::TransportError, /scheme/)
    expect do
      described_class.new.get("http://127.0.0.1:1/")
    end.to raise_error(SQRL::Client::TransportError,
                       /ECONNREFUSED|Connection refused/)
  end

  it "parses JSON bodies" do
    t = described_class.new
    t.get(site.login_url)
    expect(t.get("#{site.base_url}/sqrl/status").json).to eq("authenticated" => false, "idk" => nil, "next" => nil)
    expect(t.get(site.login_url).json).to be_nil
  end
end
