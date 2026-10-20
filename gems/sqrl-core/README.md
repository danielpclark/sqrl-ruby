# sqrl-core

A pure-Ruby implementation of the SQRL (Secure Quick Reliable Login) protocol: the
cryptography (EnScrypt, EnHash, Ed25519, X25519, AES-256-GCM via OpenSSL), the identity
key derivations and identity lock, S4 identity storage, the base56 textual identity, the
client transaction state machine and a server-side protocol handler. No runtime dependency
beyond Ruby's bundled `openssl` gem.

```ruby
require "sqrl"

# Client side: one transaction against a site
identity = SQRL::UnlockedIdentity.from_iuk(SecureRandom.random_bytes(32))
session  = SQRL::Session.new(identity, "sqrl://example.com/sqrl/cli?nut=abc", options: SQRL::ClientOptions.new(cps: true))
request  = session.query              # => Request(url:, body:, command:)
session.feed(http_post(request))      # the server's base64url body
session.state                         # => :unknown / :known / :previous_known / ...
request  = session.ident              # creates, logs in or re-keys as the answer dictates
session.feed(http_post(request))
session.cps_url                       # validated url= to send the browser to

# Server side: the protocol handler behind any HTTP framework
config  = SQRL::Server::Config.new(host: "example.com")
handler = SQRL::Server::Handler.new(config: config, stores: SQRL::Server::Memory.stores)
login   = handler.new_login_url(ip: "203.0.113.5")   # => LoginURL(url:, nut:, pending_login_id:)
result  = handler.handle(nut: nut, body: form_body, ip: client_ip)   # => Result(body:, tif:, authenticated:, cps_url:, ...)
handler.claim_cps(token)              # one-time CPS landing
handler.status(pending_login_id)      # for the browser's poller

# Identities
file = SQRL::S4Identity.parse(File.binread("me.sqrl"))
unlocked = file.unlock("password")                 # EnScrypt; a few seconds
iuk = file.unlock_iuk("1198-8748-7132-2838-8318-7570")
```

The implementation follows GRC's final specification and reproduces GRC's reference client
request bodies byte for byte; the specs include every published test vector. See the
repository README and `docs/PLAN.md` for the protocol summary and the store interfaces
(`SQRL::Server::NutStore`, `IdentityStore`, `PendingLoginStore`).
