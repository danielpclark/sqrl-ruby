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
  # sqrl.cps_token_ttl (60 s), sqrl.ask, sqrl.sin, sqrl.path_extension.
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
end
