# sqrl-core

A pure-Ruby implementation of [SQRL](https://www.grc.com/sqrl/sqrl.htm) (Secure Quick
Reliable Login): the cryptography, the identity key derivations and identity lock, S4
identity storage, the base56 textual identity, the client transaction state machine and a
server-side protocol handler with pluggable stores. Everything the other `sqrl-*` gems build
on. The only runtime dependency is Ruby's bundled `openssl` gem (3.0 or newer, which ships
with Ruby 3.1+).

## Install

```ruby
gem "sqrl-core"
```

```ruby
require "sqrl/core"   # or require "sqrl"
```

## What it implements

- **Wire protocol**: `query`, `ident`, `disable`, `enable`, `remove`; `ids`/`pids`/`urs`
  signatures over `client || server`; every TIF bit, with undefined bits aborting the
  client; `ask`/`btn` (with a server-side accept-list); `sin`/`ins`/`pins`; previous
  identities and re-keying; `sqrlonly`/`hardlock`/`cps`/`suk`/`noiptest`; the `x=` path
  extension; Alt-IDs; `can=`; Client Provided Session (`url=`). The request bodies
  reproduce GRC's reference client log byte for byte.
- **Cryptography**: EnHash, EnScrypt (iteration- and duration-based), AES-256-GCM,
  Ed25519, X25519, all through OpenSSL.
- **Identities**: IMK/ILK/IUK, per-site keys, the identity lock (RLK/SUK/VUK/URSK),
  indexed secrets; S4 identity files (type 1, 2 and 3 blocks, `sqrldata` binary and
  `SQRLDATA` text), rescue codes, password changes, re-keying with up to four previous
  identities; the base56 textual identity with check characters.
- **Server engine**: `SQRL::Server::Handler`, a port of the reference server whose state
  sits behind three store interfaces, with nut single use, `server=` echo verification,
  IP matching, identity binding, superseded handling, one-time CPS tokens, rate-limit and
  prune hooks. In-memory and Redis store sets ship here; ActiveRecord and cache sets live
  in `sqrl-rails`.

## Client: one transaction

```ruby
identity = SQRL::UnlockedIdentity.from_iuk(SecureRandom.random_bytes(32))
session  = SQRL::Session.new(identity, "sqrl://example.com/sqrl/cli?nut=…",
                             options: SQRL::ClientOptions.new(cps: true))

request = session.query                 # => Request(url:, body:, command:, client_text:)
session.feed(http_post(request))        # the server's base64url body
session.state                           # => :unknown | :known | :previous_known | :transient | :superseded | :failed
session.pending_ask                     # => SQRL::Ask or nil; answer with session.set_button(1)

request = session.ident                 # creates the account, logs in, or re-keys, as the answer dictates
session.feed(http_post(request))
session.cps_url                         # validated https URL to send the browser to (nil without cps)

session.disable                         # needs only ids
session.enable(iuk)                     # needs the IUK (rescue code) for urs
session.remove(iuk)
```

`SQRL::URL.parse` gives the site key (`site_key_bytes(alt_id)`), the POST URL and the
cancel URL. Only `sqrl://` (HTTPS) is accepted; `SQRL::Session.new(..., insecure: true)`
additionally accepts the draft-era `qrl://` for loopback hosts, which exists solely for the
browser extension's local test server.

## Server

```ruby
config  = SQRL::Server::Config.new(host: "example.com")
handler = SQRL::Server::Handler.new(config: config, stores: SQRL::Server::Memory.stores)

login  = handler.new_login_url(ip: request_ip, return_to: "/account")
login.url                               # "sqrl://example.com/sqrl/cli?nut=…" for the page and the QR code
login.pending_login_id                  # keep in the browser session; never give it to the client

result = handler.handle(nut: params["nut"], body: raw_post_body, ip: request_ip)
result.body                             # base64url text to return with status 200
result.authenticated?                   # true after a successful ident/enable
result.cps_url                          # the one-time url= handed to the client, when it asked for cps

handler.status(pending_login_id)        # {authenticated:, idk:} for the browser's poller
handler.claim_cps(token)                # PendingLogin or nil; single use, expires after cps_token_ttl
handler.prune!
```

### Config options

| Option | Default | Meaning |
| --- | --- | --- |
| `host` | `nil` | public host (with port) placed in `sqrl://` URLs; identities derive from it, so set it in production |
| `path` | `/sqrl/cli` | the endpoint path, also used in `qry=` |
| `callback_path` | `/sqrl/callback` | where the default CPS `url=` points (plus `?t=TOKEN`) |
| `insecure_http` | `false` | loopback-only testing mode issuing `qrl://`; refused for other hosts, warns once |
| `path_extension` | `nil` | `x=N`: include the first N characters of the path in the site key |
| `nut_ttl` | `300` | seconds a login-page nut stays valid |
| `cps_token_ttl` | `60` | seconds a CPS token stays claimable |
| `require_ip_match` | `true` | refuse a client whose IP differs from the browser's unless it sends `noiptest` |
| `ask` | `nil` | `SQRL::Ask` (or a callable receiving a context hash) posed in the query reply; `accept:` limits the buttons that let `ident` proceed |
| `sin` | `nil` | secret-index challenge (string or callable); the client answers with `ins`/`pins` |
| `on_unknown_identity` | `:create` | `:create` an association, `:link` only when the pending login carries a `link_user_ref`, or `:refuse` |
| `on_authenticated` | `nil` | callable `(identity, pending_login, command)` after a successful command |
| `cps_url` | `nil` | callable `(token, pending_login) -> URL` replacing the default |
| `allowed_hosts` | `nil` | strings or regexps the request host must match when `host` is derived |
| `prune_every` | `1000` | call `prune!` opportunistically every N requests (`nil` disables) |
| `before_issue` / `before_handle` | `nil` | hooks that may raise `SQRL::Server::RateLimited` |
| `clock` / `logger` | `nil` | injectable clock (tests) and logger |

### Stores

The handler keeps every record behind three small interfaces, documented in
`SQRL::Server::NutStore`, `IdentityStore` and `PendingLoginStore`:

| Store | Records | Must be atomic |
| --- | --- | --- |
| nuts | one per issued nut: pending login, expected `server=` echo, IP, bound identity, expiry | `consume` (exactly one caller wins) |
| identities | one per association: `idk`, `suk`, `vuk`, flags, `ins`, login count, `user_ref` | `rekey` |
| pending logins | one per login page view: authenticated identity, `ip_matched`, ask state, CPS token, `return_to` | `claim_cps_token` (single use) |

Implementations: `SQRL::Server::Memory.stores` (per process; development and tests),
`SQRL::Server::Redis.stores(redis: Redis.new)` (requires the `redis` gem; `GETDEL` and Lua
scripts for the single-use operations, TTLs for expiry), and in `sqrl-rails`
`SQRL::Rails::Stores::ActiveRecord` and `::Cache`. A shared "a SQRL store set" spec under
`spec/support/store_contract.rb` exercises any implementation, including concurrent
consume and claim races.

## Identities

```ruby
file = SQRL::S4Identity.parse(File.binread("me.sqrl"))     # binary "sqrldata" or "SQRLDATA" text
unlocked = file.unlock("correct horse")                      # EnScrypt over the type 1 block
iuk = file.unlock_iuk("1198-8748-7132-2838-8318-7570")        # the rescue code frees the IUK
file.to_text                                                 # "SQRLDATA…" export
SQRL::Textual.encode(file.rescue_only.to_bytes)              # base56 textual identity

new_file = SQRL::S4Identity.create(iuk, "password", SQRL::Storage.generate_rescue_code)
new_file.set_password(unlocked, "new password")
new_file.rekey(unlocked, iuk, new_iuk, "password", new_rescue_code)
```

EnScrypt cost: one scrypt iteration (N=512, r=256) takes roughly 45 ms with OpenSSL 3, so
unlocking a real identity file takes a few seconds and creating one takes the configured
password and rescue durations. Tests and bots use `SQRL::UnlockedIdentity.from_iuk`
directly and skip EnScrypt.

## Test vectors

`SQRL::TestVectors` carries every published vector: the Spec-Vectors-Identity (password,
rescue code, textual identity, IMK, per-site keys), GRC's `SQRL.log` query and ident
bodies, the EnScrypt vectors from grc.com and the newsgroup, the base56 examples validated
against GRC's client, and the Android client's sample identity file. The specs assert the
request bodies byte for byte.

## Authority and credits

GRC's specification documents (*SQRL Explained*, *Operating Details* v1.01, *Cryptography*
v1.04, *On The Wire* v1.07) are the authority. The Rust implementation in
[SQRL-extension](https://github.com/danielpclark/SQRL-extension) is one careful reading of
them and the practical source for this port; where the two differ, the documents win. SQRL
was designed by Steve Gibson of Gibson Research Corporation, who placed the specification in
the public domain.

## License

MIT. See [LICENSE](LICENSE).
