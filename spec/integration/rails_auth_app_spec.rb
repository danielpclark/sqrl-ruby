# frozen_string_literal: true

require_relative "../support/shared_examples/live_sqrl_app"

RSpec.describe "examples/rails-auth-app (live)", skip: ExampleApp.skip_reason("rails-auth-app") do
  include_context "live example app", "rails-auth-app"
  it_behaves_like "a live SQRL example app"
end
