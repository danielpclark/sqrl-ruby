# sqrl-client

A bot-capable [SQRL](https://www.grc.com/sqrl/sqrl.htm) client for Ruby: everything a
script, a test suite or an automated service needs to log in to a SQRL-enabled website
without a browser or a human. It is also the test driver for the `sqrl-*` server gems and
ships a conformance suite any SQRL server can be checked against.

```ruby
require "sqrl/client"

identity = SQRL::Client::Identity.load("bot.sqrl", password: ENV["SQRL_PASSWORD"])
agent    = SQRL::Client::Agent.new(identity: identity)
result   = agent.login("https://example.com/login")   # a login page, a sqrl:// URL or a localhost:25519 link

result.authenticated?   # => true
result.created?         # => true on the first visit (the site created the account)
result.idk              # => the site-specific public key, base64url
result.landing          # => the response of following the CPS url= (logged-in page)
agent.http.get("https://example.com/account")   # same cookie jar: already logged in
```

## Identities

| Call | Use |
| --- | --- |
| `Identity.load(path, password:)` | an S4 identity file (binary `sqrldata` or `SQRLDATA` text), as exported by any SQRL client |
| `Identity.from_textual(text, rescue_code:, password:)` | import a base56 textual identity |
| `Identity.create(password:)` | a brand-new identity; `#rescue_code` is shown once |
| `Identity.ephemeral` / `Identity.ephemeral("seed")` | an identity straight from a random or deterministic IUK, no EnScrypt; ideal for tests |
| `Identity.from_env` | `SQRL_IUK_HEX`, or `SQRL_IDENTITY_FILE` + `SQRL_PASSWORD`/`SQRL_PASSWORD_FILE` (+ `SQRL_RESCUE_CODE`) |

`enable`, `remove` and `rekey!` need the Identity Unlock Key. Ephemeral and freshly created
identities have it; file identities get it from `rescue_code:` (slow: EnScrypt).

## The agent

```ruby
agent = SQRL::Client::Agent.new(
  identity: identity,
  cps: true,                 # request a Client Provided Session and follow its url=
  unknown_site: :create,     # or :refuse to never create accounts
  options: { sqrlonly: false, hardlock: false, noiptest: false },
  alt_id: nil,
  ask_handler: ->(ask) { ask.buttons.index { |b| b.label =~ /allow/i }.to_i + 1 },
  insecure: false            # true: accept plain http and qrl:// for loopback test servers only
)

agent.login(url)                       # query → (ask) → ident; creates / logs in / re-keys as the site answers
agent.query(url)                       # does the site know me? (state :unknown / :known / :previous_known)
agent.disable(url)
agent.enable(url, rescue_code: "…")    # rescue code not needed for identities that hold the IUK
agent.remove(url, rescue_code: "…")
```

Every result carries the full `transcript` of the exchange (signatures are not recorded),
the TIF history, the cancel URL and the cookie jar. Failures raise `LoginFailed` with a
`reason` (`:disabled`, `:superseded`, `:unknown_site`, `:ip_mismatch`, `:transient`, …),
`AskRequired` when the site asks a question and no handler is set, `DiscoveryError` when no
`sqrl://` link is on the page, or `TransportError`.

Transient errors are retried with the fresh nut, previous identities are offered in turn
(`PREVIOUS_ID_MATCH` re-keys the account), `sin`/`ins` and `pins` are answered, and the CPS
`url=` is validated to point at the site before it is followed.

SQRL is `sqrl://` over HTTPS, and that is all the agent speaks by default. `insecure: true`
(CLI: `--insecure`) is a loopback-only testing mode that also accepts plain-http pages and
`qrl://` links, which the browser extension's test server and this repository's own spec
site use; `qrl://` is not part of the final SQRL specification and real clients refuse
it. A self-signed development certificate is trusted with `Transport.new(ca_file:)`
(CLI: `--ca-file`); `--no-verify-tls` turns verification off altogether.

## Capybara

```ruby
visit "/login"
SQRL::Client::Capybara.login(page, identity: SQRL::Client::Identity.ephemeral("bot"))
expect(page).to have_content("Welcome")
```

The protocol runs out of band; the **browser** then visits the one-time CPS URL, exactly as a
native client would redirect the tab, so the browser's own session is the one logged in.
`cps: false` performs `ident` only and waits for the page's poller to redirect.

## Command line

```
sqrl-client identity create  --out bot.sqrl --password-file pw.txt       # prints the rescue code once
sqrl-client identity import  --textual id.txt --rescue-code 1234-… --out bot.sqrl
sqrl-client identity show    --identity bot.sqrl [--json]
sqrl-client identity export  --identity bot.sqrl --format s4-text|textual|binary [--out FILE]
sqrl-client identity rekey   --identity bot.sqrl --password … --rescue-code …   # new IUK, old one kept as previous
sqrl-client identity change-password --identity bot.sqrl --password OLD --new-password NEW
sqrl-client identity previous --identity bot.sqrl                        # superseded identities, most recent first
sqrl-client login   https://example.com/login --identity bot.sqrl --cookies-out jar.txt [--no-cps] [--alt-id ID] [--json]
sqrl-client query | disable | enable | remove URL …                      # enable/remove need --rescue-code
sqrl-client conformance https://example.com/login [--report junit.xml] [--feature ask=on] [--only CASE,…]
```

Identities come from `--identity FILE` with `--password`/`--password-file`, from the
`SQRL_IDENTITY_FILE`/`SQRL_PASSWORD`/`SQRL_PASSWORD_FILE`/`SQRL_RESCUE_CODE` variables, or
from `--iuk-hex`/`SQRL_IUK_HEX` for throwaway test identities. `--pw-seconds` and
`--rescue-seconds` shorten EnScrypt for test identities. Exit codes: 0 success, 1 the site
refused (protocol), 2 transport failure, 3 usage.

## Conformance suite

```ruby
report = SQRL::Client::Conformance::Runner.new(login_url: "https://example.com/login").run
puts report            # PASS / FAIL / SKIP per case
report.passed?
report.to_junit_xml
```

Cases cover account creation, login with and without CPS, disable/enable/remove, re-keying
and superseded identities, `ask`/`btn`, `sin`/`ins`, Alt-IDs, nut replay, unknown nuts,
tampered requests, wrong `server=` echoes, bad signatures, identity creation without
`suk`/`vuk`, one-time CPS tokens, transient recovery and concurrent logins. Feature flags
(`features: { ask: true, sin: true, cps_single_use: false, … }`) skip what a site does not
do; a custom `site:` adapter handles pages with unusual layouts.

In RSpec:

```ruby
require "sqrl/client/conformance/rspec"

RSpec.describe "my site" do
  let(:login_url) { "http://127.0.0.1:9292/login" }
  it_behaves_like "a SQRL server"
end
```

## Command line

```
sqrl-client identity create --out bot.sqrl              # prints the rescue code once
sqrl-client identity import --textual id.txt --rescue-code … --out bot.sqrl
sqrl-client login   https://example.com/login --identity bot.sqrl --cookies-out jar.txt
sqrl-client login   https://example.com/login --iuk-hex $SQRL_IUK_HEX --json --no-cps
sqrl-client disable https://example.com/login --identity bot.sqrl
sqrl-client enable  https://example.com/login --identity bot.sqrl --rescue-code …
sqrl-client remove  https://example.com/login --identity bot.sqrl --rescue-code …
sqrl-client conformance https://example.com/login --report junit.xml --feature ask=on
```

Cookies are written in Netscape format (`curl -b jar.txt`) or JSON. Exit codes: 0 success,
1 the site refused (protocol), 2 transport failure, 3 usage.

## Limits

Ruby cannot wipe memory reliably; key material lives in ordinary Strings. Sites that show
only a QR image (no `sqrl://` link anywhere in the page) are not supported yet. SQRL for
APIs is not specified yet and therefore not implemented.
