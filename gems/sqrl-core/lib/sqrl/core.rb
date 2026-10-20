# frozen_string_literal: true

# Entry point matching the gem name: `gem "sqrl-core"` is required as `require "sqrl/core"`
# (the dash maps to a directory, as for every extension-style gem name). It loads the whole
# library; `require "sqrl"` remains available and loads the same thing.
require_relative "../sqrl"
