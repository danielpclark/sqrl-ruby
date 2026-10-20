# frozen_string_literal: true

require_relative "../support/shared_examples/live_sqrl_app"

RSpec.describe "examples/devise-app (live)", skip: ExampleApp.skip_reason("devise-app") do
  include_context "live example app", "devise-app"
  it_behaves_like "a live SQRL example app"
end
