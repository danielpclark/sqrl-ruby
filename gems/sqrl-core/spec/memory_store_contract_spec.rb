# frozen_string_literal: true

require "support/store_contract"

RSpec.describe SQRL::Server::Memory do
  let(:stores) { described_class.stores }

  it_behaves_like "a SQRL store set"
end
