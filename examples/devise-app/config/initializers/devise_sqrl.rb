# frozen_string_literal: true

# SQRL login for Devise (devise-sqrl). Protocol and storage settings are those of the
# sqrl-rails gem (SQRL::Rails::Configuration); the Devise-specific choices follow.

Rails.application.config.sqrl.tap do |sqrl|
  # The public host (and port, when not the default) placed in the sqrl:// login URLs.
  # SQRL identities are derived from this host, so it must be the name users see.
  # When nil, the host of each request is used.
  sqrl.host = ENV["SQRL_HOST"].presence

  # Storage: :active_record (default; tables from the create_sqrl_tables migration).
  sqrl.stores = :active_record

  # Protocol options: sqrl.require_ip_match (true), sqrl.nut_ttl (300 s),
  # sqrl.cps_token_ttl (60 s), sqrl.path_extension.

  # Ask the user a question on every login; ask_deny_button is the button that refuses
  # it. SQRL_ASK=1 turns the example question on for testing.
  if ENV["SQRL_ASK"].present?
    sqrl.ask = SQRL::Ask.new(message: "Allow this login?", buttons: [{ label: "Allow" }, { label: "Deny" }],
                             accept: [1])   # only "Allow" lets the ident proceed
    sqrl.ask_deny_button = 2               # and a "Deny" that slips through is refused at the callback
  end

  # Secret index challenge (sin=/ins=). SQRL_SIN=1 turns it on for testing.
  sqrl.sin = "0" if ENV["SQRL_SIN"].present?

  # Rate limit for the protocol endpoint and login page (per IP, in Rails.cache).
  # sqrl.rate_limit = { to: 60, within: 1.minute }
end

Devise.setup do |config|
  # What to do when an unknown SQRL identity completes a login:
  #   :create  create a User for it (default; see sqrl_create_resource)
  #   :link    only accept it while a user is signed in, and attach it to that user
  #   :refuse  reject it
  config.sqrl_on_unknown_identity = :create

  # How the record is built under :create. The default fills in a non-routable email
  # and a random password so :validatable passes; replace it to collect real details.
  # config.sqrl_create_resource = ->(identity, klass) { klass.new(email: "...", password: SecureRandom.hex(32)) }

  # Treat SQRL logins as "remember me" (needs :rememberable).
  config.sqrl_remember_me = false

  # Options for the login block (SQRL::Rack::LoginBlock.render): link text, QR size...
  # config.sqrl_login_block = { link_text: "Sign in with SQRL", qr_options: { size: 200 } }

  # Where to go after a failed SQRL login (default: the scope's SQRL login page).
  # config.sqrl_failure_path = "/users/sign_in"

  # Account policies: an identity that asked for "sqrlonly" cannot sign in through these
  # strategies (password logins), one that asked for "hardlock" cannot reset its
  # password. Users manage their identities at /<scope>/sqrl/identities.
  # config.sqrl_only_blocked_strategies = [:database_authenticatable]
end
