# frozen_string_literal: true

require "capybara"
require "capybara/cuprite"

# Headless Chromium through Cuprite. Honours BROWSER_PATH; falls back to the Playwright
# Chromium that the cloud environment ships, then to whatever Ferrum finds on PATH.
module BrowserSupport
  def self.browser_path
    return ENV["BROWSER_PATH"] if ENV["BROWSER_PATH"] && File.exist?(ENV["BROWSER_PATH"])

    Dir.glob("/opt/pw-browsers/chromium-*/chrome-linux*/chrome").first
  end

  def self.register!
    Capybara.register_driver(:sqrl_cuprite) do |app|
      Capybara::Cuprite::Driver.new(
        app,
        headless: true,
        browser_path: browser_path,
        timeout: 15,
        process_timeout: 30,
        # The example apps run over HTTPS with a per-run self-signed certificate.
        browser_options: { "no-sandbox" => nil, "disable-gpu" => nil, "disable-dev-shm-usage" => nil,
                           "ignore-certificate-errors" => nil }
      )
    end
    Capybara.default_driver = :sqrl_cuprite
    Capybara.javascript_driver = :sqrl_cuprite
    Capybara.default_max_wait_time = 10
  end
end

BrowserSupport.register!
