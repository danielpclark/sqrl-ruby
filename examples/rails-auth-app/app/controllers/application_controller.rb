class ApplicationController < ActionController::Base
  include Authentication
  # The stock `allow_browser versions: :modern` line is left out so that non-browser
  # clients (the sqrl-client bot used by the integration tests, curl) can reach pages.
end
