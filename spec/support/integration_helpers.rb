# frozen_string_literal: true

require "delegate"
require "sqrl/client"
require "sqrl/client/conformance"
require "sqrl/client/conformance/rspec"
require_relative "example_app"
require_relative "example_descriptors"

class ExampleApp
  # Whether an example is built enough to be booted: its own bundle is resolved and the file
  # its author creates last is present (see ExampleDescriptors).
  def self.available?(name)
    desc = ExampleDescriptors[name]
    dir = File.join(ROOT, name)
    return false unless File.exist?(File.join(dir, "Gemfile.lock"))

    ready = File.join(dir, desc.ready)
    return false unless File.exist?(ready)

    desc.ready_pattern.nil? || File.read(ready).match?(desc.ready_pattern)
  end

  def self.skip_reason(name)
    return nil if available?(name)

    "example #{name} is not built yet (missing Gemfile.lock or #{ExampleDescriptors[name].ready})"
  end

  # Why the ask/sin pass cannot run for an example yet, or nil when it can.
  def self.ask_sin_skip_reason(name)
    return skip_reason(name) if skip_reason(name)
    return nil if ExampleDescriptors[name].ask_sin_supported?(File.join(ROOT, name))

    "example #{name} does not read SQRL_ASK / SQRL_SIN yet"
  end
end

# The bot's HTTP transport for an example: a plain {SQRL::Client::Transport}, except that a
# GET of the login page runs the descriptor's +login_page+ procedure when the example needs
# one (OmniAuth's request phase is a CSRF-protected POST), so every client of the login
# URL - the agent, the conformance runner, the Site adapter - reaches the SQRL login block.
class DescriptorTransport < SimpleDelegator
  def initialize(descriptor, app, transport = SQRL::Client::Transport.new)
    super(transport)
    @descriptor = descriptor
    @app = app
    @login_url = app.url(descriptor.login_path)
  end

  def get(url, headers = {}, **kw)
    return __getobj__.get(url, headers, **kw) unless @descriptor.login_page && url.to_s == @login_url

    @descriptor.login_page.call(__getobj__, @app)
  end
end

# A conformance Site adapter driven by a descriptor: knows what a logged-in landing looks
# like for this example (the login page itself comes through DescriptorTransport).
class DescriptorSite < SQRL::Client::Conformance::Site
  def initialize(descriptor, app)
    @descriptor = descriptor
    @app = app
    super(login_url: app.url(descriptor.login_path))
  end

  def success?(response, _page = nil)
    return false if response.nil? || !response.success?

    @descriptor.logged_in.call(response.body.to_s)
  end
end

# Boots one example application for a whole example group and exposes helpers.
#
#   RSpec.describe "rack-app" do
#     include_context "live example app", "rack-app"
#     ...
#   end
RSpec.shared_context "live example app" do |app_name, env: {}|
  let(:descriptor) { ExampleDescriptors[app_name] }

  before(:all) do
    @example_app = ExampleApp.start(app_name, env: env)
  rescue StandardError => e
    raise "could not boot #{app_name}#{env.empty? ? '' : " with #{env}"}: #{e.message}"
  end

  after(:all) do
    @example_app&.stop
  end

  let(:app) { @example_app }
  let(:site) { DescriptorSite.new(descriptor, app) }
  let(:login_url) { site.login_url }

  def ephemeral(seed = nil) = SQRL::Client::Identity.ephemeral(seed)
  def new_transport = DescriptorTransport.new(descriptor, app)
  def new_agent(identity, transport: new_transport, **opts) = SQRL::Client::Agent.new(identity: identity, transport: transport, **opts)

  # Log in with +agent+ via the example's login page.
  def login_via_site(agent)
    agent.login(login_url)
  end

  def expect_logged_in(result)
    expect(result).to be_authenticated
    expect(result.cps_url).to start_with(app.base_url), "CPS url should point at the site"
    expect(result.landing).not_to be_nil
    expect(result.landing.status).to eq(200), "landing answered #{result.landing.status} at #{result.landing.final_url}"
    expect(site.success?(result.landing)).to be(true), "landing at #{result.landing.final_url} is not a logged-in page:\n#{result.landing.body[0, 400]}"
  end

  def protected_status(transport)
    transport.get(app.url(descriptor.protected_path), follow_redirects: false).status
  end

  # Asserts that a browser (Capybara session) that is not logged in cannot see the
  # protected page: either a 403, or a redirect that ends on the login page.
  def expect_browser_anonymous(page)
    if descriptor.anonymous_protected_status == 403
      expect(page.status_code).to eq(403)
    else
      expect(page.current_path).to eq(descriptor.login_path)
    end
  end
end
