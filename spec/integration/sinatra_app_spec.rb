# frozen_string_literal: true

require_relative "../support/shared_examples/live_sqrl_app"

RSpec.describe "examples/sinatra-app (live)", skip: ExampleApp.skip_reason("sinatra-app") do
  include_context "live example app", "sinatra-app"
  it_behaves_like "a live SQRL example app"
end
