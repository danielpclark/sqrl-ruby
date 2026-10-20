# frozen_string_literal: true

require_relative "../support/shared_examples/live_sqrl_app"

RSpec.describe "examples/rack-app (live)", skip: ExampleApp.skip_reason("rack-app") do
  include_context "live example app", "rack-app"
  it_behaves_like "a live SQRL example app"
end
