# Bots, automation and test suites

Gem: `sqrl-client`. Used by this repository's integration specs and runnable against any
SQRL site.

```ruby
identity = SQRL::Client::Identity.load("bot.sqrl", password: ENV["SQRL_PASSWORD"])
agent    = SQRL::Client::Agent.new(identity: identity)
result   = agent.login("https://example.com/login")
agent.http.get("https://example.com/account")   # same cookie jar, already logged in
```

- `login` discovers the `sqrl://` link on the page (or accepts a `sqrl://` URL or a
  `localhost:25519/<base64url>` link directly), sends `query` and `ident`, answers `ask`
  through `ask_handler:` and `sin` automatically, retries transient errors, offers previous
  identities, and follows the one-time CPS `url=` with the same cookie jar.
- `query`, `disable`, `enable(rescue_code:)` and `remove(rescue_code:)` cover the rest of
  the command set. Ephemeral identities (`Identity.ephemeral`) hold their unlock key, so
  tests never need a rescue code or EnScrypt.
- `SQRL::Client::Capybara.login(page, identity:)` runs the protocol out of band and then has
  the browser visit the CPS URL, so the browser session is the one logged in.
- The `sqrl-client` executable exposes the same operations and exports cookies in Netscape
  or JSON format for `curl` and friends.

## Conformance suite

```ruby
require "sqrl/client/conformance/rspec"

RSpec.describe "my SQRL server" do
  let(:login_url) { "https://example.com/login" }
  it_behaves_like "a SQRL server"
end
```

or `sqrl-client conformance https://example.com/login --report junit.xml`. The 23 cases
cover account creation, login with and without CPS, disable/enable/remove, re-keying,
Alt-IDs, nut replay, stale nuts, tampered requests, wrong `server=` echoes, bad signatures,
CPS token reuse and cross-session token use. Sites with `ask`/`sin` enable those cases
through `features:`.
