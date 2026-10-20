# frozen_string_literal: true

require "sinatra/sqrl"

RSpec.describe Sinatra::SQRL do
  let(:stores) { SQRL::Server::Memory.stores }
  let(:hook_calls) { [] }
  let(:app) do
    store = stores
    calls = hook_calls
    Class.new(Sinatra::Base) do
      set :environment, :test
      enable :sessions
      set :session_secret, SecureRandom.hex(64)
      register Sinatra::SQRL
      set :sqrl, stores: store, host: "example.com", after_login: "/protected"
      sqrl_on_login { |identity, env, pl| calls << [identity.idk_b64, env["PATH_INFO"], pl.class] }

      get("/login") { sqrl_login_block(cancel_url: "/") }
      get("/url") { sqrl_login_url }
      get("/qr") { sqrl_qr_svg }
      get("/script") { sqrl_script_tag }
      get("/protected") { sqrl_authenticated? ? "hello #{current_sqrl_identity.idk_b64}" : halt(403, "no") }
      post("/logout") do
        sqrl_logout!
        "bye"
      end
    end
  end

  it "adds the helpers" do
    browser = new_browser
    browser.get("/login")
    url = login_url_from(browser.last_response.body)
    expect(url).to start_with("sqrl://example.com/sqrl/cli?nut=")
    browser.get("/url")
    expect(browser.last_response.body).to start_with("sqrl://example.com/")
    browser.get("/qr")
    expect(browser.last_response.body).to start_with("<svg")
    browser.get("/script")
    expect(browser.last_response.body).to include('src="/sqrl/sqrl.js"')
  end

  it "logs in through the middleware with Sinatra's default protection on, runs hooks, logs out" do
    browser = new_browser
    browser.get("/login", {}, { "REMOTE_ADDR" => ClientHelpers::BROWSER_IP })
    url = login_url_from(browser.last_response.body)
    session = sqrl_login(new_client, url)
    expect(session.state).to eq(:known)
    browser.get(session.cps_url.sub("https://example.com", ""))
    expect(browser.last_response.status).to eq(303)
    expect(browser.last_response.headers["location"]).to eq("/protected")
    browser.get("/protected")
    expect(browser.last_response.body).to eq("hello #{session.idk_b64}")
    expect(hook_calls).to eq([[session.idk_b64, "/sqrl/callback", SQRL::Server::PendingLogin]])
    browser.post("/logout")
    browser.get("/protected")
    expect(browser.last_response.status).to eq(403)
  end

  it "works as a classic-style registration with set :sqrl after register" do
    store = stores
    klass = Class.new(Sinatra::Base) do
      set :environment, :test
      register Sinatra::SQRL
      enable :sessions
      set :session_secret, SecureRandom.hex(64)
      get("/login") { sqrl_login_block(qr: false) }
    end
    klass.set :sqrl, stores: store, host: "late.example"
    browser = new_browser(klass)
    browser.get("/login")
    expect(login_url_from(browser.last_response.body)).to start_with("sqrl://late.example/")
  end

  it "explains a missing session" do
    klass = Class.new(Sinatra::Base) do
      set :environment, :test
      register Sinatra::SQRL
      set :sqrl, host: "example.com"
      set :raise_errors, true
      set :show_exceptions, false
      get("/login") { sqrl_login_url }
    end
    expect { new_browser(klass).get("/login") }.to raise_error(SQRL::Rack::Error, /enable :sessions/)
  end
end
