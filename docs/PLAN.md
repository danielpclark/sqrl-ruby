# SQRL Login for Ruby – Implementation Plan

Status: implemented on branch `claude/kind-babbage-dduewx` (see §10 for what each milestone delivered) · Date: 2026-10-20 · Repository: `danielpclark/ruby_sqrl`

This document is the master plan for bringing **SQRL (Secure Quick Reliable Login)** to the
Ruby ecosystem: a protocol core, server-side integrations for Rack/Sinatra, OmniAuth,
Devise and Rails' built-in authentication, and a bot-capable client library that doubles as
the project's own test driver. It is written so that each milestone can be picked up as an
independent unit of work.

---

## Table of contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [Background and reference material](#2-background-and-reference-material)
3. [Architecture overview](#3-architecture-overview)
4. [`sqrl-core`: protocol and cryptography](#4-sqrl-core-protocol-and-cryptography)
5. [Server-side engine (`SQRL::Server`)](#5-server-side-engine-sqrlserver)
6. [Framework integrations](#6-framework-integrations)
   - 6.1 [Rack and Sinatra (`sqrl-rack`)](#61-rack-and-sinatra-sqrl-rack)
   - 6.2 [OmniAuth (`omniauth-sqrl`)](#62-omniauth-omniauth-sqrl)
   - 6.3 [Rails engine and Rails 8 Authentication (`sqrl-rails`)](#63-rails-engine-and-rails-8-authentication-sqrl-rails)
   - 6.4 [Devise (`devise-sqrl`)](#64-devise-devise-sqrl)
7. [Bot-capable client (`sqrl-client`)](#7-bot-capable-client-sqrl-client)
8. [Testing strategy](#8-testing-strategy)
9. [Repository layout](#9-repository-layout)
10. [Milestones and acceptance criteria](#10-milestones-and-acceptance-criteria)
11. [Security requirements checklist](#11-security-requirements-checklist)
12. [For later](#12-for-later)
13. [Open decisions](#13-open-decisions)
14. [Appendix A – Protocol cheat sheet](#appendix-a--protocol-cheat-sheet)
15. [Appendix B – Test vectors and flows to port](#appendix-b--test-vectors-and-flows-to-port)
16. [Appendix C – Rust to Ruby module map](#appendix-c--rust-to-ruby-module-map)
17. [Phase 2 – depth, hardening and reach](#15-phase-2--depth-hardening-and-reach)

---

## 1. Goals and non-goals

### Goals

- **G1 – A complete, spec-faithful SQRL implementation in Ruby.** Client and server halves of
  the wire protocol, the identity cryptography (EnScrypt, EnHash, identity lock), S4
  identity storage and the textual identity format, matching GRC's final specification and
  byte-for-byte compatible with GRC's reference client and the Rust implementation in
  `danielpclark/SQRL-extension`.
- **G2 – "Just works" server integrations.** Adding one gem and one line of configuration
  gives an existing login system SQRL support, in the idiom of each framework:
  - Rack middleware and a Sinatra extension;
  - an OmniAuth strategy (`provider :sqrl`);
  - a Devise module (`devise :sqrl_authenticatable`);
  - a Rails engine plus generator that plugs into the `rails generate authentication`
    stack shipped with Rails 8.
- **G3 – An official bot client.** A gem that lets scripts, test suites and automation log
  in to any SQRL-enabled website without a browser or a human: identity management,
  the full command set (`query`, `ident`, `disable`, `enable`, `remove`), `ask`/`btn`,
  `sin`/`ins`, re-keying, Client Provided Session (CPS) handoff, and page discovery of
  `sqrl://` links. The same gem is the driver for this project's integration tests.
- **G4 – Full-stack verification.** Every integration is exercised end to end against a
  live example application of its own framework, both by the bot client and by a headless
  browser, and the whole suite runs in CI.

### Non-goals (for the first release)

- A graphical identity manager or end-user client UI (the browser extension covers that).
- SQRL for APIs (bearer-style, non-browser authentication). The specification for this
  does not exist yet; see [§12 For later](#12-for-later).
- Alternative cryptographic back ends (libsodium, JRuby). OpenSSL ≥ 3.0 via Ruby's bundled
  `openssl` gem covers everything; see §4.2.

---

## 2. Background and reference material

### 2.1 What SQRL requires of an implementation

A SQRL login is a sequence of HTTPS `POST`s from the client to the site's SQRL endpoint.
Each body is `client=<b64u>&server=<b64u>&ids=<b64u>[&pids=…][&urs=…]`:

- `client` is a CRLF-separated `name=value` list (`ver`, `cmd`, `idk`, optional `pidk`,
  `suk`, `vuk`, `opt`, `btn`, `ins`, `pins`).
- `server` is, on the first request, the complete `sqrl://` URL as received; afterwards
  it is the server's previous response **verbatim**.
- `ids` is the Ed25519 signature, by the per-site identity key, over the concatenation of
  the `client` and `server` base64url strings; `pids` is the same signature by a previous
  identity; `urs` by the Unlock Request Signing Key.

The server answers with a base64url-encoded CRLF list carrying at least `ver`, `nut`,
`tif` (hex transaction information flags) and `qry` (the path of the next POST), and
optionally `url` (CPS success URL), `sin`, `suk`, `ask`, `can`.

The identity cryptography derives everything from one 256-bit secret, the Identity Unlock
Key (IUK):

| Key | Derivation | Used for |
| --- | --- | --- |
| IMK (Identity Master Key) | `EnHash(IUK)` | every per-site key |
| ILK (Identity Lock Key) | `X25519(IUK, basepoint)` | identity lock given to sites |
| per-site seed | `HMAC-SHA256(key = IMK, msg = site key string)` | Ed25519 seed → `idk`, `ids` |
| INK | `EnHash(per-site seed)` | `ins = HMAC-SHA256(INK, sin)` |
| RLK (Random Lock Key) | fresh random per account creation | — |
| SUK (Server Unlock Key) | `X25519(RLK, basepoint)` | stored by server |
| VUK (Verify Unlock Key) | `Ed25519 public key of seed X25519(RLK, ILK)` | stored by server |
| URSK | `Ed25519 seed = X25519(IUK, SUK)` | signs `urs` for `enable`/`remove`/re-key |

`EnHash` is 16 chained SHA-256 iterations XOR-ed together. `EnScrypt` is iterated,
XOR-chained scrypt with `N = 512, r = 256, p = 1` over an NFKC-normalised password, by
iteration count or by time. The S4 storage format holds the IMK/ILK (type 1, password
EnScrypt), the IUK (type 2, rescue-code EnScrypt) and up to four previous IUKs (type 3),
all AES-256-GCM with the block header as authenticated plaintext.

The **site key** is the lower-cased host of the `sqrl://` URL (user info and port
stripped) plus, when the URL carries `x=N`, the first `N` characters of the path. An Alt-ID
appends `0x00` and the Alt-ID to the site key.

### 2.2 Reference implementation to port

`danielpclark/SQRL-extension` (Rust, MIT) is the authoritative source for this port. Its
`crates/sqrl-core` crate implements every piece above and is verified against every
published test vector, and its reference server (`sqrl-core/src/server.rs`, feature
`server`) defines the server behaviour this plan reproduces, including nut single-use,
IP matching, identity binding to the session, re-keying, `ask`/`btn`, `sin`/`ins`, and
CPS `url=` generation. `crates/sqrl-core/tests/vectors.rs` and `tests/flows.rs` are the
test corpus to port (Appendix B). `crates/sqrl-test-server` is a stand-alone SQRL site that
the Ruby bot client will be tested against for cross-implementation interoperability.

Nothing in this plan writes to that repository; it is read-only reference.

### 2.3 Specification sources

- GRC: *SQRL Explained*, *SQRL Operating Details* v1.01, *SQRL Cryptography* v1.04,
  *SQRL On The Wire* v1.07 (late 2019), and the spec pages at <https://www.grc.com/sqrl/>.
- `grc.sqrl` newsgroup rulings, as already distilled into the Rust implementation. Where an
  older decision was later reversed, the later one is used.
- GRC's SSP API server endpoint conventions (`/cli.sqrl`, the `localhost:25519` CPS probe)
  for compatibility with existing clients and sites.

---

## 3. Architecture overview

The project is a monorepo of small gems with a strict dependency direction. The core has
**no runtime dependencies** beyond Ruby's bundled `openssl` gem; everything
framework-specific sits in its own gem so that applications pull in only what they use.

```
                    ┌─────────────────┐
                    │   sqrl-core     │  crypto · identity · S4 · textual · url ·
                    │  (pure Ruby)    │  protocol (client Session + server Handler)
                    └────────┬────────┘
            ┌────────────────┼──────────────────────┐
            ▼                ▼                      ▼
   ┌────────────────┐ ┌────────────────┐   ┌──────────────────┐
   │   sqrl-rack    │ │ omniauth-sqrl  │   │   sqrl-client    │  bot / automation
   │ middleware,    │ │ strategy       │   │ Agent, CLI,      │  library and the
   │ Sinatra ext,   │ └────────────────┘   │ Capybara helper, │  project's own test
   │ sqrl.js, QR    │                      │ Conformance suite│  driver
   └───────┬────────┘                      └──────────────────┘
           ▼
   ┌────────────────┐
   │   sqrl-rails   │  engine, generator, ActiveRecord stores,
   │                │  Rails 8 Authentication adapter
   └───────┬────────┘
           ▼
   ┌────────────────┐
   │  devise-sqrl   │  Devise module, Warden strategy, controller, routes
   └────────────────┘
```

| Gem | Namespace | Purpose | Runtime deps |
| --- | --- | --- | --- |
| `sqrl-core` | `SQRL` | Protocol, crypto, identity storage, server engine, in-memory stores | `openssl` (bundled) |
| `sqrl-rack` | `SQRL::Rack`, `Sinatra::SQRL` | Rack endpoint middleware, Sinatra extension, browser script, QR helper | `sqrl-core`, `rack` ≥ 2.2, `rqrcode` |
| `omniauth-sqrl` | `OmniAuth::Strategies::SQRL` | OmniAuth strategy | `sqrl-core`, `sqrl-rack`, `omniauth` ≥ 2.0 |
| `sqrl-rails` | `SQRL::Rails` | Engine, `sqrl:install` generator, ActiveRecord stores, Rails 8 `Authentication` adapter | `sqrl-rack`, `rails` ≥ 7.1 |
| `devise-sqrl` | `Devise::Models::SqrlAuthenticatable` | Devise module | `sqrl-rails`, `devise` ≥ 4.9 |
| `sqrl-client` | `SQRL::Client` | Bot client, CLI, Capybara helper, conformance suite | `sqrl-core`, `http-cookie` |

Naming note: the gem name `sqrl` is already registered on rubygems.org by an unrelated
2013 placeholder (version 0.0.0, owner `mbarnard`), so the core is named `sqrl-core`. All
six names above were free at the time of writing. See [§13](#13-open-decisions).

Supported versions (proposed): Ruby ≥ 3.1 for `sqrl-core` and `sqrl-client` (needs the
`openssl` gem ≥ 3.0 for raw Ed25519/X25519 keys), Ruby ≥ 3.2 for the Rails gems; Rack 2.2
and 3.x; Sinatra 3 and 4; Rails 7.1 through 8.1; Devise 4.9 and 5.0; OmniAuth 2.x.

---

## 4. `sqrl-core`: protocol and cryptography

### 4.1 Module map

```
lib/sqrl.rb
lib/sqrl/version.rb
lib/sqrl/errors.rb           SQRL::Error < StandardError; FormatError, CryptoError, ProtocolError
lib/sqrl/util.rb             base64url (no padding), hex, constant-time compare, secure random,
                             best-effort wiping of String/IO buffers
lib/sqrl/crypto.rb           sha256, hmac_sha256, enhash, scrypt_once, enscrypt_iterations,
                             enscrypt_duration, aes_gcm_encrypt/decrypt, ed25519_*, x25519_*
lib/sqrl/identity.rb         key derivations (imk_from_iuk, ilk_from_iuk, site_seed,
                             indexed_secret, make_server_lock, unlock_request_seed) and
                             SQRL::UnlockedIdentity (IMK, ILK, previous IUKs)
lib/sqrl/storage.rb          S4: Type1Block, Type2Block, Type3Block, S4Identity (parse,
                             to_bytes, to_text, create, unlock, unlock_iuk, set_password, rekey),
                             rescue-code generation/normalisation, option flags, settings
lib/sqrl/textual.rb          base56 textual identity encode/decode with line check characters
lib/sqrl/url.rb              SQRL::URL: parse sqrl:// and loopback-only qrl://, site key,
                             post_url, post_url_for_qry, cancel URL, resolve, same_host?
lib/sqrl/protocol.rb         TIF, Command, ClientOptions, Ask/AskButton, parse_pairs,
                             version_supported, ServerResponse
lib/sqrl/protocol/session.rb SQRL::Session: the client transaction state machine
lib/sqrl/server.rb           SQRL::Server::Handler (port of ReferenceServer#handle),
                             Result, LoginURL issuance, CPS tokens
lib/sqrl/server/stores.rb    NutStore / IdentityStore / PendingLoginStore interfaces
lib/sqrl/server/memory.rb    in-memory store implementations (tests, Sinatra demos)
lib/sqrl/test_vectors.rb     the published vectors as constants, shared by all suites
```

A one-to-one map from the Rust modules is in Appendix C. Porting is deliberately literal:
same function boundaries, same names where Ruby allows, same error cases, so that the
Rust test corpus can be transliterated rather than re-invented.

### 4.2 Cryptographic primitives via OpenSSL

All primitives are available from Ruby's bundled `openssl` gem (verified on Ruby 3.3.6 with
OpenSSL 3.0.13):

| Need | Ruby call |
| --- | --- |
| scrypt (`N=512, r=256, p=1`, 32 bytes) | `OpenSSL::KDF.scrypt(pw, salt:, N: 512, r: 256, p: 1, length: 32)` |
| SHA-256 / HMAC-SHA256 | `OpenSSL::Digest::SHA256`, `OpenSSL::HMAC` |
| AES-256-GCM with AAD and 16-byte tag | `OpenSSL::Cipher.new("aes-256-gcm")` |
| Ed25519 from a 32-byte seed | `OpenSSL::PKey.new_raw_private_key("ED25519", seed)`; `#sign(nil, msg)`, `#raw_public_key` |
| Ed25519 verify | `OpenSSL::PKey.new_raw_public_key("ED25519", pk).verify(nil, sig, msg)` |
| X25519 scalar mult / basepoint | `OpenSSL::PKey.new_raw_private_key("X25519", k).derive(peer)`; `#raw_public_key` |
| CSPRNG | `OpenSSL::Random.random_bytes` / `SecureRandom` |
| NFKC | `String#unicode_normalize(:nfkc)` |

Notes and risks:

- scrypt with these parameters needs 16 MiB; OpenSSL's default `maxmem` (32 MiB) is
  sufficient. OpenSSL in FIPS mode disables scrypt; detect and raise a clear error.
- EnScrypt cost: one scrypt call takes tens of milliseconds in C. GRC's defaults (about 180
  iterations for the password, 5 seconds for the rescue code) remain practical. Tests use
  small iteration counts; vectors fix the iteration count explicitly.
- Key wiping: Ruby cannot guarantee memory zeroisation. The library overwrites `String`
  buffers it owns (`String#clear` after `replace` with zero bytes, `#freeze`-free), keeps
  secrets out of exception messages and `inspect`, and documents the limitation. This is a
  best-effort measure, not a security claim.
- Timing: all comparisons of signatures, MACs and tokens use `OpenSSL.fixed_length_secure_compare`.

### 4.3 Client session (`SQRL::Session`)

A direct port of the Rust `Session`: constructed from an `UnlockedIdentity`, a parsed
`SQRL::URL`, `ClientOptions` and an optional Alt-ID; builds signed `Request` objects
(`url`, `body`, `command`, `client_text`) for `query`, `ident`, `disable`, `enable(iuk)`,
`remove(iuk)`; `feed(body)` parses and validates the server response; `state` returns one
of `:no_response, :unknown, :known, :previous_known, :transient, :superseded, :failed`
with `disabled` and message detail; `cps_url` validates `url=` against the site host;
`cancel_url`, `pending_ask`, `set_button`, `try_next_previous`, `ip_check_failed?`.

Invariants carried over from the reference client:

- `suk` is requested with every command; `sqrlonly`/`hardlock` are never sent with `remove`.
- A response with TIF bits outside `0x3FF` aborts the transaction.
- `qry` must be a server-relative path on the original host; `url=` must point at the same
  host; `ask` button URLs are forced onto the site origin.
- `qrl://` is accepted for loopback hosts only.
- Previous identities are offered most-recent first; re-keying sends the new `suk`/`vuk`
  and a `urs` signed with the previous identity's URSK.

### 4.4 Server handler (`SQRL::Server::Handler`)

A port of `ReferenceServer#handle`, with the in-memory `HashMap`s replaced by the three
store interfaces in §5.2 and with every policy point exposed as configuration. It is a
pure function of (nut, form body, client IP, stores, config) → `Result`, with no HTTP
knowledge, so the same handler backs all four framework integrations and the in-process
flow tests.

---

## 5. Server-side engine (`SQRL::Server`)

### 5.1 Request lifecycle

```
 browser                     site (Rack app + SQRL::Server)                     SQRL client
   │  GET /login                   │                                              │
   │──────────────────────────────▶│ issue nut; store {nut → pending_login,       │
   │  page: sqrl:// link, QR,      │   expected server=, ip, bound_idk=nil}       │
   │  sqrl.js (CPS probe + poll)   │                                              │
   │◀──────────────────────────────│                                              │
   │  click / scan ───────────────────────────────────────────────────────────────▶│
   │                               │  POST /sqrl/cli?nut=…  (query)               │
   │                               │◀─────────────────────────────────────────────│
   │                               │  consume nut (single use); verify server=    │
   │                               │  echo, ids/pids, version, IP; look up idk;   │
   │                               │  answer tif + fresh nut + qry (+suk/ask/sin) │
   │                               │─────────────────────────────────────────────▶│
   │                               │  POST qry  (ident, cps)                      │
   │                               │◀─────────────────────────────────────────────│
   │                               │  create / login / re-key; mark pending_login │
   │                               │  authenticated(idk); mint one-time CPS token;│
   │                               │  reply url=https://site/sqrl/callback?t=TOKEN│
   │                               │─────────────────────────────────────────────▶│
   │  (CPS) client navigates the browser to url= ─────────────────────────────────│
   │  GET /sqrl/callback?t=TOKEN   │                                              │
   │──────────────────────────────▶│ claim token (single use, bound to pending     │
   │                               │ login + browser session); hand idk to the    │
   │                               │ framework adapter → user session; redirect   │
   │  — or (no CPS) —              │                                              │
   │  GET /sqrl/status (poll, cookie-bound) → {"authenticated":true, "next": url} │
```

Design decisions that differ from the minimal Rust test server, on purpose:

- **CPS landing uses a one-time token, not the session id.** The pending-login id lives in
  the browser's own session cookie; the CPS `url=` carries a separate random token that is
  claimed exactly once and expires quickly (default 60 s). The poll endpoint never reveals
  the token; it only reports state for the pending login bound to the caller's cookie.
- **Pending logins are bound to the browser session** so that an attacker who obtains a
  `sqrl://` URL from one browser cannot complete a login into another browser's session
  (the "login the victim into the attacker's account" class of issue). When `IPS_MATCHED`
  is absent and the client did not send `noiptest`, the handler refuses, as the spec
  requires; the integration additionally lets the site require `IPS_MATCHED` for
  non-CPS completions.
- **Nut single-use is atomic** at the store level (compare-and-set / `UPDATE … WHERE
  used_at IS NULL` returning one row), not read-then-write.

### 5.2 Store interfaces

Each integration provides implementations; `sqrl-core` ships in-memory ones.

```ruby
module SQRL::Server
  # Nuts: issued per login page and per response; consumed exactly once.
  class NutStore
    def issue(nut, pending_login_id:, expected_server:, ip:, bound_idk:, expires_at:) end
    def consume(nut) end          # → record or nil; atomic; marks used
    def prune!(now = Time.now) end
  end

  # One record per SQRL association (idk) on this site.
  class IdentityStore
    def find(idk) end             # → Identity(idk, suk, vuk, disabled, sqrlonly, hardlock, ins, user_ref)
    def create(attrs) end
    def update(idk, attrs) end
    def rekey(old_idk, new_idk, suk:, vuk:, ins:) end   # moves association, marks old superseded
    def superseded?(idk) end
    def remove(idk) end
  end

  # One record per login page view, keyed by an opaque id kept in the browser session.
  class PendingLoginStore
    def create(id, ip:, return_to:, expires_at:) end
    def find(id) end              # → PendingLogin(authenticated_idk, btn, asked, last_command, cps_token)
    def update(id, attrs) end
    def claim_cps_token(token) end  # → PendingLogin or nil; atomic single use
  end
end
```

Implementations planned: `SQRL::Server::Memory::*` (core), `SQRL::Rails::Stores::ActiveRecord::*`
(tables `sqrl_identities`, `sqrl_nuts`, `sqrl_pending_logins`), and a cache-backed
`PendingLoginStore`/`NutStore` for `ActiveSupport::Cache` stores that support atomic
`delete`-with-return (Redis, Memcached); the file/memory cache stores are rejected with a
clear error in production.

### 5.3 Configuration (`SQRL::Server::Config`)

| Option | Default | Meaning |
| --- | --- | --- |
| `host` | request host | Host (with port) placed in issued `sqrl://` URLs; must be the public host |
| `path` | `/sqrl/cli` | SQRL endpoint path, also used in `qry=` |
| `scheme` | `sqrl` (`qrl` for loopback in development/test) | URL scheme issued |
| `path_extension` | `nil` | `x=N` to scope identities to a path prefix |
| `nut_ttl` | 5 minutes | Login page nut lifetime |
| `cps_token_ttl` | 60 seconds | Lifetime of the CPS landing token |
| `require_ip_match` | `true` | Enforce `IPS_MATCHED` unless the client sends `noiptest` |
| `trusted_proxies` | framework's | How the client IP is determined |
| `ask` | `nil` | `Ask` to pose in the query reply (static or a lambda receiving context) |
| `sin` | `nil` | Secret index challenge (static or lambda) |
| `on_unknown_identity` | `:create` | `:create` (auto account), `:link` (require signed-in user), `:refuse` |
| `on_authenticated` | — | callback `(identity, pending_login, command)` |
| `logger` | — | protocol trace logging with secrets redacted |

### 5.4 Browser-side script (`sqrl.js`)

A dependency-free script served by `sqrl-rack` and the Rails engine:

1. Performs the standard same-device CPS probe (`http://localhost:25519/<random>.gif`);
   when a local client answers, rewrites the login link to
   `http://localhost:25519/<base64url sqrl url>` so native clients and the browser extension
   can redirect the tab straight into the logged-in session.
2. Polls `/sqrl/status` (cookie-bound) for non-CPS logins (phone scanning the QR) and
   navigates to the returned `next` URL when authenticated.
3. Renders nothing itself; the markup (link, QR `<svg>`, status text) comes from a view
   helper so that each framework can style it. The helper's default markup is accessible
   (link text, `aria-live` status).

QR codes are generated server-side as SVG with `rqrcode` (pure Ruby) so no image endpoint
is needed.

---

## 6. Framework integrations

The common contract for all four: the integration mounts the SQRL endpoint, the status
endpoint and the CPS callback; renders the login block; and translates an authenticated
`idk` into that framework's notion of a signed-in user. Everything below the "user" line is
`sqrl-core`/`sqrl-rack`; everything above it is per framework.

### 6.1 Rack and Sinatra (`sqrl-rack`)

**Rack middleware** `SQRL::Rack::Middleware` (requires a session middleware upstream):

```ruby
use Rack::Session::Cookie, secret: ENV.fetch("SESSION_SECRET")
use SQRL::Rack::Middleware,
    stores: SQRL::Server::Memory.stores,              # or your own
    host: "example.com",
    on_login: ->(env, identity) { env["rack.session"]["user_id"] = User.for_sqrl(identity.idk).id },
    after_login: "/"
```

It serves `POST <path>` (the SQRL endpoint; exempt from any CSRF layer because it is
authenticated by signatures), `GET /sqrl/status` and `GET /sqrl/callback`, and exposes
`env["sqrl.server"]` (a request-scoped facade: `login_url`, `qr_svg`, `script_tag`,
`identity`) to the application.

**Sinatra extension** `Sinatra::SQRL`:

```ruby
require "sinatra/sqrl"
class App < Sinatra::Base
  enable :sessions
  register Sinatra::SQRL
  set :sqrl, host: "example.com", stores: SQRL::Server::Memory.stores

  get "/login" do
    erb :login   # uses sqrl_login_block, or sqrl_login_url + sqrl_qr_svg + sqrl_script_tag
  end
  get "/" do
    sqrl_authenticated? ? "Hello #{current_sqrl_identity.idk}" : redirect("/login")
  end
end
```

Helpers: `sqrl_login_url`, `sqrl_qr_svg`, `sqrl_script_tag`, `sqrl_login_block`,
`sqrl_authenticated?`, `current_sqrl_identity`, `sqrl_logout!`, and the
`sqrl_on_login { |identity| … }` hook. Sinatra's `protection` (Rack::Protection) must skip
the SQRL endpoint for `http_origin`/`authenticity_token` checks; the extension configures
this.

Bare-metal Rack (no Sinatra) is the first example app, to prove the middleware alone is
enough.

### 6.2 OmniAuth (`omniauth-sqrl`)

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :sqrl, stores: SQRL::Rails::Stores.active_record, host: "example.com"
end
```

Strategy `OmniAuth::Strategies::SQRL`:

- **Request phase** (`POST /auth/sqrl`, OmniAuth 2's CSRF-protected form or button): issues
  a pending login bound to `rack.session`, and renders the login page (QR, link, `sqrl.js`).
  A `request_path` option allows embedding the login block in the host app's own page
  instead.
- **Other phase** (`respond_to?(:other_phase)` hook in `OmniAuth::Strategy#call!`): serves
  `POST /auth/sqrl/cli` and `GET /auth/sqrl/status` directly from the middleware stack, so
  no Rails controller or CSRF exemption is involved.
- **Callback phase** (`GET /auth/sqrl/callback?t=TOKEN`, reached by CPS redirect or by the
  poller): claims the token, verifies it belongs to this `rack.session`, and builds the
  auth hash:

```ruby
{ provider: "sqrl",
  uid: "<idk base64url>",
  info: {},                               # SQRL carries no profile data by design
  credentials: {},
  extra: { sqrl: { suk:, vuk:, created: true/false, rekeyed_from: "<old idk>" | nil,
                   options: { sqrlonly:, hardlock: }, tif: 0x05 } } }
```

- Failure mapping: expired or foreign token → `fail!(:invalid_credentials)`; identity
  disabled → `fail!(:sqrl_disabled)`; superseded → `fail!(:identity_superseded)`.
- OmniAuth's `test_mode` is supported via `OmniAuth.config.mock_auth[:sqrl]`.
- Works unchanged under `devise :omniauthable, omniauth_providers: [:sqrl]` for people who
  prefer the OmniAuth path over `devise-sqrl`.

### 6.3 Rails engine and Rails 8 Authentication (`sqrl-rails`)

**Engine** `SQRL::Rails::Engine` (isolated namespace `SQRL::Rails`):

- Controllers: `CliController#create` (SQRL endpoint; `skip_forgery_protection`),
  `StatusController#show`, `CallbackController#show`, plus `LoginsController#new` for a
  stand-alone login page.
- Models: `SQRL::Rails::Identity` (`sqrl_identities`), `Nut`, `PendingLogin`, with the
  ActiveRecord store adapters from §5.2 and a `sqrl:prune` rake task / `ActiveJob`.
- View helpers: `sqrl_login_block`, `sqrl_login_url`, `sqrl_qr_svg`, `sqrl_script_tag`
  (asset served through Propshaft or Sprockets; importmap pin provided).
- Configuration: `Rails.application.config.sqrl` (a `SQRL::Server::Config` plus
  `sign_in`, `user_class`, `on_unknown_identity`).

**Rails 8 `rails generate authentication` adapter.** The generator in Rails 8 creates an
`Authentication` concern (`start_new_session_for(user)`, `resume_session`,
`terminate_session`, `allow_unauthenticated_access`, `after_authentication_url`), a
`Session` model, `Current.session` and a `SessionsController`. `sqrl-rails` plugs into it:

```
bin/rails generate authentication     # Rails' own
bin/rails generate sqrl:install       # ours
```

`sqrl:install` does the following, each step idempotent and skippable:

1. Adds migrations for `sqrl_identities` (`user:references`, `idk:string` unique, `suk`,
   `vuk`, `disabled`, `sqrlonly`, `hardlock`, `ins`, `superseded_by`, `last_login_at`),
   `sqrl_nuts` and `sqrl_pending_logins`.
2. Inserts `has_many :sqrl_identities, class_name: "SQRL::Rails::Identity"` into `User`.
3. Mounts the engine: `mount SQRL::Rails::Engine, at: "/sqrl"`.
4. Writes `config/initializers/sqrl.rb` with the host, `on_unknown_identity` and the sign-in
   adapter. When the `Authentication` concern is detected, the default is:

   ```ruby
   config.sqrl.sign_in = ->(controller, user) { controller.send(:start_new_session_for, user) }
   config.sqrl.after_sign_in = ->(controller) { controller.send(:after_authentication_url) }
   ```

   `CallbackController` includes the host application's `::Authentication` concern when it
   exists (and calls `allow_unauthenticated_access`), so `start_new_session_for` runs with
   the app's own cookie settings.
5. Adds `<%= sqrl_login_block %>` to `app/views/sessions/new.html.erb` when that file exists.
6. Adds a system test scaffold using `sqrl-client`'s Capybara helper.

Unknown identities default to `:create` (a `User` with no password; `has_secure_password`
needs `validations: false` or a generated random password, handled by the generator) in
line with SQRL's account-creation story; `:link` requires a signed-in user and attaches the
identity to `Current.user`.

The engine also works without the Rails 8 concern: any app can set `config.sqrl.sign_in`.

### 6.4 Devise (`devise-sqrl`)

```ruby
# Gemfile: gem "devise-sqrl"
class User < ApplicationRecord
  devise :database_authenticatable, :registerable, :sqrl_authenticatable
end
```

Registration (in `lib/devise/sqrl.rb`, loaded by `require "devise-sqrl"`):

```ruby
Devise.add_module :sqrl_authenticatable,
  strategy: true,                   # Warden strategy Devise::Strategies::SqrlAuthenticatable
  controller: :sqrl,                # Devise::SqrlController
  route: :sqrl,                     # ActionDispatch::Routing::Mapper#devise_sqrl
  model: "devise/models/sqrl_authenticatable",
  no_input: true
```

- **Routes** (`devise_sqrl(mapping, controllers)`): `GET  /users/sqrl` (login page or
  JSON for XHR), `POST /users/sqrl/cli` (endpoint, forgery protection skipped),
  `GET /users/sqrl/status`, `GET /users/sqrl/callback`.
- **Warden strategy** `valid?` when the request is the SQRL callback with a token (or the
  session carries a freshly claimed SQRL login); `authenticate!` claims the token, resolves
  `resource_class.find_for_sqrl(identity)` and calls `success!(user)`; respects
  `active_for_authentication?` (confirmable, lockable) and Devise's `sign_in` hooks,
  trackable, rememberable (`remember_me` option on the login block).
- **Model module** `Devise::Models::SqrlAuthenticatable`: `has_many :sqrl_identities`,
  `find_for_sqrl(identity)`, `link_sqrl_identity!(identity)`, `unlink_sqrl_identity!`,
  and class-level config `Devise.sqrl_on_unknown_identity` mirroring §5.3.
- **Controller** `Devise::SqrlController < DeviseController` using the engine's handler;
  overridable like any Devise controller (`controllers: { sqrl: "users/sqrl" }`).
- **Views**: `devise/sqrl/new.html.erb` and a `devise/shared/_sqrl` partial; the generator
  `rails g devise:sqrl:install` adds the partial to `sessions/new` and the migration.
- Store adapters: reuses `sqrl-rails`' ActiveRecord stores and migrations.

---

## 7. Bot-capable client (`sqrl-client`)

The official automation client: everything a script needs to behave like a SQRL client
without a human, and the library this project's integration tests drive. It is also usable
as a library by other people's test suites and by services that need to log in to
SQRL-only sites.

### 7.1 Components

```
lib/sqrl/client.rb
lib/sqrl/client/identity.rb     load/create/unlock S4 files, textual identities, ephemeral identities
lib/sqrl/client/transport.rb    HTTP: Net::HTTP default with cookie jar (http-cookie), TLS options,
                                proxy, timeouts, retry of TRANSIENT_ERROR; pluggable (Faraday adapter)
lib/sqrl/client/agent.rb        high-level bot: login, create_account, disable, enable, remove,
                                answer_ask, policies, event hooks
lib/sqrl/client/discovery.rb    find the SQRL link on a login page
lib/sqrl/client/result.rb       LoginResult: idk, tif history, cps_url, landing response, cookies
lib/sqrl/client/capybara.rb     drive a Capybara session through a SQRL login
lib/sqrl/client/conformance.rb  the reusable server conformance suite (see §8.3)
lib/sqrl/client/cli.rb          `sqrl-client` executable
```

### 7.2 Identities for bots

- `SQRL::Client::Identity.load(path, password:)` – an S4 `.sqrl` file (binary or
  `SQRLDATA` text) unlocked with a password; `.from_textual(text, rescue_code:)`;
  `.create(password:, rescue_code: nil)` writes a new S4 file and returns the rescue code.
- `SQRL::Client::Identity.ephemeral(seed = nil)` – an identity straight from a 32-byte IUK,
  skipping EnScrypt entirely. Deterministic from a seed for reproducible tests; the
  conformance suite uses this so it runs in seconds.
- Credentials from the environment for CI: `SQRL_IDENTITY_FILE`, `SQRL_PASSWORD` or
  `SQRL_PASSWORD_FILE`, `SQRL_RESCUE_CODE` (only for `enable`/`remove`/re-key),
  `SQRL_IUK_HEX` for ephemeral identities.
- The unlocked identity is kept in memory for the agent's lifetime; the derived password
  key can be cached (`cache_key: true`) to avoid repeated EnScrypt in long-running bots.

### 7.3 The agent

```ruby
agent = SQRL::Client::Agent.new(identity: SQRL::Client::Identity.load("bot.sqrl", password: ENV["SQRL_PASSWORD"]),
                                unknown_site: :create,   # or :refuse
                                cps: true, options: { sqrlonly: false, hardlock: false },
                                ask_handler: ->(ask) { ask.buttons.index { |b| b.label =~ /allow/i } || 0 })

result = agent.login("https://example.com/login")   # a page URL, a sqrl:// URL, or a localhost:25519 CPS link
result.authenticated?   # => true
result.idk              # base64url
result.cookies          # the logged-in session cookies (HTTP::CookieJar), ready for further requests
result.landing          # response of following the CPS url= (or nil without CPS)
agent.http              # the same cookie-carrying transport, for the bot's next requests
```

`login` performs: discovery (§7.4) → `query` (walking previous identities on
`PREVIOUS_ID_MATCH`, retrying once on `TRANSIENT_ERROR`) → optional `ask` answer →
`ident` (login, account creation or re-key as the server's answer dictates) → CPS: GET the
validated `url=` with the same cookie jar; without CPS: optionally poll a site-provided
status URL. `disable`, `enable(rescue_code:)`, `remove(rescue_code:)` follow the same
shape. Every wire exchange is recorded (`result.transcript`) with secrets redacted, for
debugging and for the conformance reports.

### 7.4 Page discovery

Given an HTML page, the agent finds the login link in this order: `a[href^="sqrl://"]`
(and `qrl://` on loopback hosts), `href="http://localhost:25519/<base64url>"` CPS-style
links (decoded back to the `sqrl://` URL), `data-sqrl-url` attributes, and finally any
`sqrl://` URL in the page text. Parsing uses a small tolerant scanner by default and
Nokogiri when it is available. Sites that only show a QR image are out of scope for the
first release (decoding needs a native dependency; see §12).

### 7.5 Capybara helper (for test suites and browser automation)

```ruby
SQRL::Client::Capybara.login(page, identity: bot_identity)   # page is the Capybara session
```

Reads the `sqrl://` link from the current page, performs the protocol out of band with
`cps: true`, and then has the **browser** visit the returned `url=`, exactly as a native
client would redirect the tab. The browser's session cookie is therefore the one that gets
logged in, which exercises the integration's real CPS path. A `cps: false` variant performs
`ident` and lets the page's own poller finish the login, exercising the status endpoint.

### 7.6 CLI

```
sqrl-client identity create  --out bot.sqrl                       # prints the rescue code once
sqrl-client identity import  --textual id.txt --rescue-code … --out bot.sqrl
sqrl-client login   https://example.com/login --identity bot.sqrl --cookies-out jar.txt [--no-cps] [--json]
sqrl-client disable https://example.com/login --identity bot.sqrl
sqrl-client enable  https://example.com/login --identity bot.sqrl --rescue-code …
sqrl-client remove  https://example.com/login --identity bot.sqrl --rescue-code …
sqrl-client conformance https://example.com/login [--report junit.xml]
```

Cookies export in Netscape and JSON formats so `curl` and other tools can continue the
session. Exit codes distinguish protocol failures (TIF) from transport failures.

---

## 8. Testing strategy

Testing is layered so that each layer fails for exactly one kind of reason.

### 8.1 Unit tests with published vectors (`sqrl-core`)

Port `crates/sqrl-core/tests/vectors.rs` verbatim (Appendix B): EnScrypt vectors
(Spec-Vectors-Identity password and QuickPass hint, the 16/32-byte salt newsgroup vectors),
the Spec-Vectors-Identity textual identity → rescue code → IUK/IMK/ILK, the `query` and
`ident` POST bodies that must reproduce GRC's client log byte for byte, and the base56
examples validated against GRC's client. Plus S4 round-trips (binary and text, unknown
block preservation, duplicate block rejection, edition counter, password change, re-key
with four previous identities), URL parsing cases (`x=`, `X=`, user info, ports, IPv6,
`can=`, Alt-ID), TIF parsing and the undefined-bits abort, and `ServerResponse` parsing.

### 8.2 In-process flow tests (`sqrl-core`)

Port `tests/flows.rs`: client `Session` against `Server::Handler` with memory stores and a
fake clock, no HTTP: account creation then login with CPS; disable/enable/remove with the
rescue code; re-key moves the account; older previous identities tried in turn;
enable/remove via a previous identity need no rescue code; `ask`/`btn`; `sin`/`ins`;
transient-error recovery; tampering detection (modified `client`, replayed `server`,
wrong signature, nut reuse); IP mismatch refused unless `noiptest`; a different identity
mid-session is `BAD_ID_ASSOCIATION`; Alt-ID yields a different identity. New cases for the
Ruby design: CPS token single use and expiry, pending login bound to the browser session,
store atomicity under concurrent `consume`.

### 8.3 Conformance suite (`SQRL::Client::Conformance`)

A framework-neutral runner that takes a login page URL and a factory for fresh identities,
and executes the full behavioural matrix against a live server:

| Group | Cases |
| --- | --- |
| Happy paths | create account (CPS), login (CPS), login without CPS via poll, logout/login again |
| Account commands | disable → login refused with `SQRL_DISABLED`, enable with rescue code, remove, re-create |
| Re-keying | previous identity matched → `ident` re-keys, old idk `IDENTITY_SUPERSEDED` |
| Server options | `ask`/`btn` round trip, `sin`/`ins` stored and re-checked, `x=` path extension, Alt-ID |
| Negative | nut replay, stale nut, tampered `client`, wrong `server` echo, bad `ids`, foreign `qry`, undefined TIF bit, IP mismatch, CPS token reuse, CPS token from another browser session, callback without token |
| Robustness | `TRANSIENT_ERROR` retry, concurrent logins, pruning of expired nuts |

Exposed three ways: a plain Ruby API returning a report object, RSpec shared examples
(`it_behaves_like "a SQRL server"`), and the `sqrl-client conformance` CLI. Every example
application in §8.4 must pass it; third parties can run it against their own servers.

### 8.4 Live example applications (one per framework)

Each lives under `examples/`, has its own `Gemfile`, boots stand-alone with `bin/dev`, and
is a real, minimal application of its framework with a home page, a login page, a
protected page and logout:

| Example | Stack | Proves |
| --- | --- | --- |
| `examples/rack-app` | bare Rack + `Rack::Session::Cookie` + `SQRL::Rack::Middleware` | middleware alone is sufficient |
| `examples/sinatra-app` | Sinatra 4 + `Sinatra::SQRL` | extension helpers, Rack::Protection interplay |
| `examples/omniauth-app` | Sinatra + OmniAuth (`provider :sqrl`), and a Rails variant with `devise :omniauthable` | strategy phases, auth hash, failure routes |
| `examples/rails-auth-app` | Rails 8.1 generated with `rails g authentication` then `rails g sqrl:install` | generator output, Rails 8 session integration |
| `examples/devise-app` | Rails 8 + Devise 5 + `devise :sqrl_authenticatable` | Warden strategy, routes, views, confirmable/lockable interplay |

Integration tests (`spec/integration/<example>_spec.rb`) boot the example on a random port
with Puma, run the conformance suite through `sqrl-client`, and then run framework-specific
assertions (for example: Devise `current_user` set, trackable columns updated; Rails 8
`Session` row created with the browser's user agent; OmniAuth auth hash contents).

### 8.5 Browser tests

Capybara with Cuprite (headless Chromium) against each example: the login page renders the
QR and link, `sqrl.js` falls back to polling when no local client answers the `:25519`
probe, a CPS login via `SQRL::Client::Capybara.login` lands the browser on the protected
page, a non-CPS login completes through the poller, and the "cancel" link follows `can=`.

### 8.6 Cross-implementation interoperability

- **Ruby client ↔ Rust server**: a CI job clones `danielpclark/SQRL-extension`, builds
  `sqrl-test-server` with Cargo, and runs the conformance suite's happy-path and account
  command groups against it (the Rust server supports `SQRL_ASK` and `SQRL_SIN`).
- **Rust/wasm client ↔ Ruby server**: the extension's `tests/smoke.mjs` client logic,
  pointed at the Sinatra example, run under Node. This is a stretch goal because it needs
  the wasm build toolchain in CI; it may run on a nightly schedule only.
- **GRC's reference**: a manual rake task to log in to GRC's public SQRL demo with a
  throwaway identity. Never run automatically.

### 8.7 CI matrix and quality gates

- GitHub Actions: Ruby 3.1/3.2/3.3/3.4 for the core and client; Rails 7.1/7.2/8.0/8.1 ×
  Devise 4.9/5.0; Sinatra 3/4; Rack 2.2/3.x. Appraisal-style Gemfiles under `gemfiles/`.
- RuboCop (shared config), `bundle exec rake` per gem, coverage with SimpleCov, YARD docs
  build, `bundler-audit`. A release workflow tags and pushes all gems together.
- EnScrypt timing smoke test to catch pathological OpenSSL builds (one iteration must take
  under 200 ms on the CI runner).

---

## 9. Repository layout

```
ruby_sqrl/
├── README.md
├── docs/
│   ├── PLAN.md                     this document
│   ├── protocol.md                 Ruby-oriented protocol notes (grows out of Appendix A)
│   ├── security.md                 threat model, store requirements, deployment notes
│   └── integrations/               one guide per framework
├── Gemfile, Rakefile               monorepo tooling (runs every gem's suite)
├── gems/
│   ├── sqrl-core/
│   ├── sqrl-rack/
│   ├── omniauth-sqrl/
│   ├── sqrl-rails/
│   ├── devise-sqrl/
│   └── sqrl-client/
├── examples/
│   ├── rack-app/
│   ├── sinatra-app/
│   ├── omniauth-app/
│   ├── rails-auth-app/
│   └── devise-app/
├── spec/
│   ├── integration/                boots examples, runs conformance + browser tests
│   └── support/                    example app launcher, port allocation, Cuprite setup
├── gemfiles/                       version matrix for CI
└── .github/workflows/              ci.yml, interop.yml, release.yml
```

Each gem keeps the conventional `lib/`, `spec/`, `*.gemspec`, `CHANGELOG.md`, and is
publishable on its own; versions move in lockstep (`SQRL::VERSION`).

---

## 10. Milestones and acceptance criteria

Each milestone is intended to be one or a few pull requests and ends in a green CI run.

| # | Milestone | Deliverables | Done when |
| --- | --- | --- | --- |
| M0 | Repository scaffolding | monorepo layout, gemspecs, shared RuboCop, CI skeleton, docs stubs, MIT license | `bundle exec rake` runs an empty suite on the matrix |
| M1 | `sqrl-core` cryptography and identity | `crypto`, `identity`, `storage`, `textual`, `url`, test vectors | every vector in Appendix B passes; S4 round-trips; GRC's sample identity imports and exports identically |
| M2 | `sqrl-core` protocol | `protocol`, `Session`, `Server::Handler`, memory stores, config | all flow tests pass; the `query`/`ident` bodies match GRC's log bytes |
| M3 | `sqrl-client` | identities, transport, agent, discovery, CLI, conformance runner | conformance suite passes against the in-process handler served by a throwaway Rack app, and against the Rust `sqrl-test-server` |
| M4 | `sqrl-rack` + Rack and Sinatra examples | middleware, Sinatra extension, `sqrl.js`, QR helper, two example apps, browser tests | both examples pass conformance and Cuprite tests |
| M5 | `omniauth-sqrl` + example | strategy, failure mapping, test mode, example app | example passes conformance; auth hash contract tests pass; works under `devise :omniauthable` |
| M6 | `sqrl-rails` + Rails 8 example | engine, ActiveRecord stores and migrations, `sqrl:install` generator, Rails 8 `Authentication` adapter, importmap/Propshaft asset | a fresh `rails new` + `rails g authentication` + `rails g sqrl:install` app passes conformance with zero manual edits |
| M7 | `devise-sqrl` + example | module, Warden strategy, routes, controller, views, generator | example passes conformance; confirmable/lockable/trackable/rememberable interplay tests pass |
| M8 | Hardening and 0.1.0 | security review against §11, docs per integration, CHANGELOGs, release workflow, interop job | all gems published; README quick-starts verified from scratch |

Rough ordering rationale: M1–M3 produce a testable client before any framework code
exists, so every later milestone starts with its test driver already in hand.

**Status (2026-10-20):** M0 through M8 are delivered on the branch. Counts at the end of
phase 1: 351 gem examples, 165 live integration examples across the five example apps,
4 interop examples against the Rust reference server, all green. What phase 1 left out, and
the order it is picked up in, is in [§15 Phase 2](#15-phase-2--depth-hardening-and-reach).

---

## 11. Security requirements checklist

Carried into code review for every milestone.

- [ ] Nuts are unpredictable (≥ 64 bits of randomness plus a counter), single use, bound to
      the pending login, the issuing IP and (after the first command) the identity.
- [ ] The `server=` echo must equal the previously issued value byte for byte.
- [ ] `ids`, `pids` and `urs` are verified before any state change; `urs` against the stored
      VUK (or the previous identity's VUK during re-key).
- [ ] `IPS_MATCHED` enforced unless `noiptest`; a bare `0x40` refusal otherwise.
- [ ] Superseded identities are refused with `IDENTITY_SUPERSEDED`; an identity change
      mid-transaction is `BAD_ID_ASSOCIATION`.
- [ ] `qry` is always a path on the issuing host; `url=` and `can=` resolve to the site.
- [ ] CPS landing tokens are random, single use, short-lived and tied to the browser
      session that started the login; the status endpoint reveals nothing to other sessions.
- [ ] The SQRL endpoint is exempt from CSRF/origin checks but nothing else is.
- [ ] Client-side: TIF bits outside `0x3FF` abort; `qrl://` only for loopback; the CPS
      `url=` host is checked before following it; cookies are never sent cross-host.
- [ ] Secrets never reach logs, exceptions or `inspect`; transcripts are redacted.
- [ ] Store adapters document their atomicity guarantees; non-atomic caches are refused in
      production.
- [ ] Rate limiting hooks on the endpoint and on login-page issuance (nut flooding).

---

## 12. For later

Deliberately out of the first release; tracked here so the design leaves room for them.

1. **SQRL for APIs.** No specification exists yet for bearer-style SQRL authentication of
   API calls. The client keeps `Session` transport-agnostic and the server keeps
   `Handler` HTTP-agnostic so that a future scheme (for example, an `Authorization:
   SQRL client=…, server=…, ids=…` header carrying a server-issued challenge, or an
   `ident`-derived token exchange) can be added as a new transport and a new Rack
   middleware without touching the protocol core. Work item: write the spec proposal first
   (challenge issuance, replay protection, token lifetime), prototype it in `sqrl-rack`,
   then add `Agent#api_token`.
2. **GRC SSP API compatibility layer** (`/nut.sqrl`, `/png.sqrl`, `/pag.sqrl`,
   `/cps.sqrl`), so sites written against GRC's SSP server can swap in the Ruby engine.
3. **QR image decoding in the bot** (for sites that show only a QR), via an optional
   native dependency.
4. **Alternative crypto back ends**: `rbnacl` for speed, a pure-Ruby fallback for JRuby.
5. **Identity management UI** for Rails (list, disable, unlink SQRL identities) as Hotwire
   components.
6. **Managed secrets**: loading bot identities from secret managers; QuickPass-style
   caching for interactive CLIs.
7. **ActionCable push** instead of polling for non-CPS logins.

---

## 13. Open decisions

Decisions the plan makes provisionally; please confirm or change.

1. **Gem names.** `sqrl` is taken by a third party on rubygems.org. Decided (2026-10-20):
   keep `sqrl-core`, `sqrl-rack`, `omniauth-sqrl`, `sqrl-rails`, `devise-sqrl` and
   `sqrl-client`. The dash follows the RubyGems convention for gems that extend another
   library (`omniauth-github`, `rspec-rails`); `sqrl-core` and `sqrl-client` keep the
   family prefix for consistency. Asking the owner of `sqrl` for a transfer remains an
   option for the core.
2. **Test framework.** RSpec for all gems and the integration suite, with the conformance
   suite also usable from Minitest. Rails example apps keep Rails' Minitest for their own
   generated tests.
3. **Minimum versions.** Ruby 3.1 (core/client) and 3.2 (Rails gems); Rails ≥ 7.1; Devise
   ≥ 4.9; Rack ≥ 2.2; Sinatra ≥ 3.
4. **Default unknown-identity policy.** `:create` (auto-create an account), matching SQRL's
   design; `:link` for sites that require an existing account.
5. **Monorepo.** One repository (`ruby_sqrl`) with six gems released in lockstep, versus
   one repository per gem. The plan assumes the monorepo.
6. **License.** MIT, matching the browser extension.

---

## Appendix A – Protocol cheat sheet

**Client `client=` parameters**: `ver=1`, `cmd=query|ident|disable|enable|remove`,
`idk`, `pidk`, `suk`, `vuk`, `opt=sqrlonly~hardlock~cps~suk~noiptest`, `btn=0|1|2`,
`ins`, `pins`. **Form fields**: `client`, `server`, `ids`, `pids`, `urs`.

**Server response parameters**: `ver`, `nut`, `tif` (hex), `qry`, `url`, `sin`, `suk`,
`ask=<message>~<label>[;<url>]~<label>[;<url>]`, `can`.

**TIF bits**

| Bit | Name | Meaning |
| --- | --- | --- |
| 0x001 | ID_MATCH | current identity known |
| 0x002 | PREVIOUS_ID_MATCH | previous identity known |
| 0x004 | IPS_MATCHED | request IP equals the nut's IP |
| 0x008 | SQRL_DISABLED | SQRL login disabled for the account |
| 0x010 | FUNCTION_NOT_SUPPORTED | unknown command |
| 0x020 | TRANSIENT_ERROR | retry with the fresh nut |
| 0x040 | COMMAND_FAILED | command not executed |
| 0x080 | CLIENT_FAILURE | malformed or failed verification |
| 0x100 | BAD_ID_ASSOCIATION | identity differs from the one that started the transaction |
| 0x200 | IDENTITY_SUPERSEDED | identity was re-keyed |

Any bit above 0x200 is undefined in protocol version 1 and aborts the client.

**Server decision order** (from the reference server): nut lookup and single use →
form fields present → `server=` echo matches → `client` decodes → version, command, `idk`
→ `ids` (and `pids` if `pidk`) verify → identity bound to the session → IP check →
superseded check → ID/previous-ID match and disabled flag → `btn` bookkeeping → re-key
when a previous identity matched and new `suk`/`vuk`/`urs` were supplied → execute command
→ attach `suk` when requested, disabled, or previous-matched → respond with fresh nut.

**Site key**: `lowercase(host)` + first `x` characters of the path; Alt-ID appends
`"\0" + alt_id`. **First `server=`**: base64url of the `sqrl://` URL exactly as received.
**Signature message**: the ASCII bytes of `client_b64 + server_b64`.

## Appendix B – Test vectors and flows to port

From `crates/sqrl-core/tests/vectors.rs`:

- `enscrypt_spec_vectors_identity_password` – password `Zingo-Bingo-Slingo-Dingo`, salt
  `F5019F96E9F64D32BEAE43145ACEF2CF`, 179 iterations → `bc151224…e36d`.
- `enscrypt_spec_vectors_quickpass_hint` – hint `Zing`, salt `CD2E1EA56DE20FE036B6D2FA867DF50A`,
  31 iterations → `ddc7f5d1…b9d9`.
- `enscrypt_newsgroup_vectors_16_and_32_byte_salts`.
- `spec_vectors_identity_textual_rescue_code_and_keys` – the published textual identity
  (`KKcC 3BaX akxc …`), rescue code `1198-8748-7132-2838-8318-7570`, expected IMK
  `2E471E10…2BA8`.
- `spec_vectors_identity_query_and_ident_signatures` – byte-exact `query` and `ident` bodies
  from GRC's `SQRL.log`.
- `base56_vectors_validated_against_grc_client`.

From `crates/sqrl-core/tests/flows.rs`: `create_account_then_login_with_cps`,
`disable_enable_remove_with_rescue_code`, `rekey_moves_account_to_new_identity`,
`older_previous_identities_are_tried_in_turn`,
`enable_and_remove_via_previous_identity_do_not_need_rescue_code`, `ask_and_btn`,
`sin_and_ins`, `transient_error_recovers_with_fresh_query`, `tampering_is_detected`,
`ip_mismatch_is_refused_unless_noiptest`, `different_identity_mid_session_is_bad_association`,
`alt_id_yields_a_different_identity_on_the_same_site`.

The vector constants are copied into `lib/sqrl/test_vectors.rb` so every gem's suite can
reference the same values.

## Appendix C – Rust to Ruby module map

| Rust (`crates/sqrl-core/src`) | Ruby (`gems/sqrl-core/lib/sqrl`) | Notes |
| --- | --- | --- |
| `util.rs` | `util.rb` | base64url without padding; `random_array` → `SecureRandom.bytes` |
| `crypto.rs` | `crypto.rb` | OpenSSL for everything; `enscrypt_duration` takes a clock lambda for tests |
| `identity.rs` | `identity.rb` | `UnlockedIdentity`; `ServerLock` as a `Data` struct |
| `storage.rs` | `storage.rb` | `S4Identity`, block types, flags, rescue code helpers |
| `textual.rs` | `textual.rb` | base56 with check characters |
| `url.rs` | `url.rb` | `SQRL::URL` (avoids clashing with `::URI`) |
| `protocol.rs` (types) | `protocol.rb` | `Tif` as an immutable value object with predicate methods |
| `protocol.rs` (`Session`) | `protocol/session.rb` | identical state machine and request builder |
| `server.rs` | `server.rb`, `server/*.rb` | state behind store interfaces; CPS token added |
| `../sqrl-test-server` | `examples/rack-app` | same routes, plus the status/callback contract from §5.1 |
| `tests/vectors.rs`, `tests/flows.rs` | `spec/vectors_spec.rb`, `spec/flows_spec.rb` | one-to-one |

---

## 15. Phase 2 – depth, hardening and reach

Phase 1 built every layer once and proved it end to end. Phase 2 takes each layer to the
depth a production deployment and a public gem release need. Items are grouped into four
milestones; within a milestone they are independent and can run in parallel.

### P1 – Protocol features surfaced to applications

SQRL carries account-policy signals that phase 1 stored but did not act on.

| Item | What | Done when |
| --- | --- | --- |
| P1.1 `sqrlonly` / `hardlock` enforcement | A user whose identity requested `sqrlonly` must not be able to log in with a password; `hardlock` must block non-SQRL account recovery. Devise: a model hook that fails `database_authenticatable` and `recoverable` for such users with a clear message. Rails 8 adapter and Rack facade: `sqrl_only?(user)` / `hard_locked?(user)` helpers plus guidance for the generated `SessionsController` and `PasswordsController`. | Devise and Rails example apps refuse password login and password reset for a `sqrlonly` / `hardlock` identity; specs in `devise-sqrl` and `sqrl-rails`. |
| P1.2 Identity management | Users can see the SQRL identities linked to their account, unlink one, and see when it last logged in. Rails engine controller and views (plain ERB), Devise variant under the mapping, model methods already present. `last_login_at` and `logins` kept current on every successful `ident`/`enable`. | Request specs; the Rails and Devise examples expose the page. |
| P1.3 `ask` and `sin` in every example | Each example honours `SQRL_ASK=1` / `SQRL_SIN=1` (as the Rust test server does) so the conformance cases for `ask`/`btn` and `sin`/`ins` run live. The integration harness boots every app a second time with both enabled. | The 10 pending `ask`/`sin` integration cases pass. |
| P1.4 Client identity operations | `sqrl-client identity export` (S4 text and textual), `identity rekey`, `identity change-password`, `--alt-id` on every command, `--previous` listing. | CLI specs; README. |

### P2 – Production readiness

| Item | What | Done when |
| --- | --- | --- |
| P2.1 Host handling | Explicit `host` strongly defaulted: a warning when derived from the request, an optional `allowed_hosts` list, and a bounded per-host handler cache (security review item 7). | Specs for the cap and the allowlist; docs updated. |
| P2.2 Pruning and rate-limit hooks | Opportunistic `prune!` every N handled requests (configurable), `before_issue` / `before_handle` hooks on the config for rate limiting, Rails `rate_limit` on the cli and login-page controllers when available (review item 8). | Specs; a Rack::Attack recipe in the docs. |
| P2.3 Stores for non-Rails apps | A Redis-backed `SQRL::Server::Redis` store set (optional `redis` gem, atomic `GETDEL` / Lua for the compare-and-set) and an `ActiveSupport::Cache` set for Rails apps that prefer cache stores, each with the store conformance spec shared with the memory and ActiveRecord sets. | A shared "store contract" spec passes for every implementation. |
| P2.4 Remaining review items | `qrl://` only for real loopback IPv6 literals, escaped `extra_attrs` keys, broader rescue-to-failure in the Rails callback, constant-time comparisons everywhere a secret is compared. | Each has a spec. |
| P2.5 Release engineering | `release.yml` that builds and pushes all six gems from a tag, `changelog_uri` and friends in every gemspec, a lenient shared RuboCop configuration with a CI lint job, `bundler-audit`, YARD build check. | A dry-run `gem build` of all six succeeds in CI; lint is green. |
| P2.6 Version matrix | Appraisal-style gemfiles for Rails 7.1 / 7.2 / 8.0 and Devise 4.9, run in CI for `sqrl-rails` and `devise-sqrl`. | Matrix green. |

### P3 – Reach

| Item | What | Done when |
| --- | --- | --- |
| P3.1 Roda | A `plugin :sqrl` shipped inside `sqrl-rack` (`roda/plugins/sqrl`) wrapping the middleware with Roda-style helpers, a `roda-app` example, and its row in the integration harness. | The Roda example passes the live suite. |
| P3.2 Docs | `docs/security.md` (threat model, store requirements, deployment checklist) and `docs/protocol.md` (the Ruby-facing protocol notes grown from Appendix A), an "other Rack frameworks" section. | Written and linked from the README. |
| P3.3 Browser-side polish | `sqrl.js` emits `sqrl:authenticated` / `sqrl:expired` DOM events, supports a `data-sqrl-poll` backoff, and exposes `SQRL.refresh()` to fetch a fresh nut when one expires without a page reload (needs a small `GET /sqrl/refresh` endpoint). | Cuprite specs. |
| P3.4 Reverse interop | The Rust extension's Node smoke client against the Sinatra example on a scheduled CI job. | Job green on schedule. |

### P4 – Specification work (kept separate on purpose)

| Item | What |
| --- | --- |
| P4.1 API authentication | Write `docs/api-auth.md`: a proposal for SQRL-authenticated API calls (challenge issuance, request signing header, replay protection, token exchange), review it against the SQRL community's prior discussions, then prototype as a new transport in `sqrl-client` and a middleware in `sqrl-rack`. No implementation before the proposal is agreed. |
| P4.2 GRC SSP API compatibility | Study GRC's SSP API server endpoints (`/nut.sqrl`, `/png.sqrl`, `/pag.sqrl`, `/cps.sqrl`, …) and decide whether a compatibility layer belongs in `sqrl-rack`. |
| P4.3 ActionCable / SSE push | Replace polling with a push channel for non-CPS logins where the host app has ActionCable or wants Server-Sent Events. |

### Order of work

P1 and P2 run together (they touch different files); P3.1 and P3.2 can start at once; P3.3
after P2.2 (it adds an endpoint); P3.4 and P4 after everything else is green.

### Status (2026-10-20, end of phase 2)

Delivered: P1.1–P1.4, P2.1–P2.6, P3.1–P3.3, and the P4.1 proposal document
(`docs/api-auth.md`). Counts: 475 gem examples, 240 live integration examples across six
example applications (each booted twice, the second time with `ask` and `sin` enabled),
4 interop examples, RuboCop clean, Rails 7.1/7.2/8.0 matrix green for `sqrl-rails` and
`devise-sqrl`.

Open: P3.4 (reverse interop job), P4.2 (SSP API study) and P4.3 (push channel), plus the
P4.1 prototype once the proposal is agreed.
