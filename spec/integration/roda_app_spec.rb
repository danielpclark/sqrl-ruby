# frozen_string_literal: true

require_relative "../support/shared_examples/live_sqrl_app"
require_relative "../support/shared_examples/live_sqrl_app_ask_sin"

RSpec.describe "examples/roda-app (live)", skip: ExampleApp.skip_reason("roda-app") do
  include_context "live example app", "roda-app"
  it_behaves_like "a live SQRL example app"

  describe "with SQRL_ASK=1 and SQRL_SIN=1", skip: ExampleApp.ask_sin_skip_reason("roda-app") do
    include_context "live example app", "roda-app", env: ExampleDescriptors::ASK_SIN_ENV
    it_behaves_like "a live SQRL example app with ask and sin"
  end
end
