# SQRL protocol notes for Ruby

A Ruby-oriented summary of the parts of SQRL that the gems implement. The authoritative
sources are GRC's specification documents (*SQRL Explained* v1.03, *Operating Details* v1.01,
*Cryptography* v1.04, *On The Wire* v1.07, all October–December 2019); where they are
ambiguous the gems follow Steve Gibson's latest ruling in the `grc.sqrl` newsgroup
(news.grc.com, cited here as `grc.sqrl:<article>`), his later word superseding earlier,
abandoned designs.

## Keys

| Name | Derivation | Where it lives |
| --- | --- | --- |
| IUK | 256 random bits | S4 type 2 block, encrypted with the rescue code |
| IMK | `EnHash(IUK)` | S4 type 1 block, encrypted with the password |
| ILK | `X25519(IUK, basepoint)` | S4 type 1 block |
| per-site seed | `HMAC-SHA256(IMK, site_key)` | derived on demand |
| `idk` | Ed25519 public key of the per-site seed | sent to the site |
| INK | `EnHash(per-site seed)` | derived on demand |
| `ins` | `HMAC-SHA256(INK, sin)` | sent when the site set `sin=` |
| RLK | random per account creation | discarded |
| `suk` | `X25519(RLK, basepoint)` | stored by the site |
| `vuk` | Ed25519 public key of `X25519(RLK, ILK)` | stored by the site |
| URSK seed | `X25519(IUK, suk)` | derived when the rescue code is available |

`site_key` is the lower-cased host of the `sqrl://` URL (user info and port stripped), plus
the first `x` characters of the path when the URL carries `x=`, plus `"\0" + alt_id` for an
Alt-ID (the NUL separator is Gibson's April 2019 ruling, grc.sqrl:22238: `domain [+ext]
[+ 0x00 + Alt-ID]`; the *SQRL Explained* PDF only says "appended"). In Ruby:
`SQRL::URL.parse(url).site_key_bytes(alt_id)`.

`EnHash` is 16 chained SHA-256 iterations XOR-ed together. `EnScrypt` is scrypt with
`N = 512, r = 256, p = 1, dkLen = 32`, iterated with each output as the next salt and all
outputs XOR-ed, for a fixed count or a fixed duration. Passwords are NFKC-normalised first.

## Wire format

Request body (`application/x-www-form-urlencoded`, values already base64url):

```
client=<b64u(CRLF list)>&server=<b64u>&ids=<b64u(64 bytes)>[&pids=…][&urs=…]
```

`client` list: `ver=1`, `cmd=query|ident|disable|enable|remove`, `idk`, optional `pidk`,
`suk`, `vuk`, `opt=sqrlonly~hardlock~cps~suk~noiptest`, `btn`, `ins`, `pins`.
`server` is the `sqrl://` URL for the first request and the previous response verbatim
afterwards. Signatures cover the ASCII bytes of `client_b64 + server_b64`.

Response body (base64url of a CRLF list): `ver=1`, `nut`, `tif=<hex>`, `qry=<path>`, and
optionally `url` (CPS), `sin`, `suk`, `ask=<message>~<label>[;<url>]…`, `can`.

In Ruby: `SQRL::Session` builds requests and parses responses; `SQRL::ServerResponse.parse`
and `SQRL::Protocol.parse_pairs` are the low-level pieces.

## TIF

| Bit | Name |
| --- | --- |
| 0x001 | ID_MATCH |
| 0x002 | PREVIOUS_ID_MATCH |
| 0x004 | IPS_MATCHED |
| 0x008 | SQRL_DISABLED |
| 0x010 | FUNCTION_NOT_SUPPORTED |
| 0x020 | TRANSIENT_ERROR |
| 0x040 | COMMAND_FAILED |
| 0x080 | CLIENT_FAILURE |
| 0x100 | BAD_ID_ASSOCIATION |
| 0x200 | IDENTITY_SUPERSEDED |

`SQRL::Tif` wraps the value with predicate methods; any bit above 0x200 makes
`Tif#defined?` false and the client aborts.

The bits describe the account *after* the command ran: the reply to the `ident` that re-keys
an account has 0x01 set and 0x02 clear. A superseded identity (one the site has already seen
as a `pidk`) is refused with exactly `0x240`. When 0x40 is set, no bit other than 0x80
carries meaning.

## Scheme

`sqrl://` is the only scheme and it means HTTPS: the client POSTs to `https://` + the rest
of the URL. The draft-era `qrl://` (plain HTTP) is not part of final SQRL; the gems parse it
only in the explicit loopback testing mode described in `docs/security.md`.

## A transaction

1. The site renders `sqrl://host/path?nut=N` (`SQRL::Server::Handler#new_login_url`).
2. The client sends `query`. The reply says whether `idk` (or `pidk`) is known, whether
   SQRL is disabled for the account, and may pose an `ask` (only here, and only when 0x01
   is set).
3. The client sends `ident` (with `suk`/`vuk` for a new account, with `pidk`/`pids`/`urs`
   and new `suk`/`vuk` to re-key, with `btn` to answer an `ask`). A re-key also clears any
   disabled state, since the `urs` carries the rescue code's authority.
4. `disable` needs only `ids`; `enable` and `remove` need `urs` under the URSK, which needs
   the IUK (rescue code), unless only a previous identity matched (then the previous IUK
   signs). Every successful non-query command copies the `sqrlonly`/`hardlock` state the
   client sent (their absence clears the flags).
5. The reply to *every* command carries `suk=` when the client asked with `opt=suk` (GRC's
   client always does), when the account is disabled, or when a previous identity matched
   (Gibson, grc.sqrl:12289, January 2016; On The Wire v1.07).
6. With `cps`, the reply to every non-query command carries `url=`, and the server never
   signs in the browser that showed the login page: only the browser the client redirects to
   that one-time URL is signed in (`SQRL::Rack::Endpoint` refuses the poll for such logins).
7. `TRANSIENT_ERROR` (stale or unknown nut) means: retry once with the new nut. The gems'
   server keeps its state by reference, so the retry draws the identical error; two identical
   errors in a row tell the client that the login page has expired and must be refreshed
   (Gibson, grc.sqrl:23543, November 2019). `SQRL::Client::Agent` raises `LoginFailed` with
   that message.

## Client Provided Session

Native clients and the browser extension listen on `http://localhost:25519/`. A login page
probes it with an image load; when something answers, the page points its link at
`http://localhost:25519/<base64url sqrl url>` so the client can redirect the tab to the
site's `url=` after `ident`. `sqrl.js` in `sqrl-rack` implements the page side; `sqrl-client`
understands both link forms.

## Identity storage (S4)

`sqrldata` (binary) or `SQRLDATA` (base64url text) followed by length-prefixed blocks:
type 1 (IMK and ILK under the password key, with settings and the EnScrypt parameters),
type 2 (IUK under the rescue-code key), type 3 (up to four previous IUKs under the IMK, with
an edition counter). AES-256-GCM with the plaintext header as additional authenticated
data. `SQRL::S4Identity` reads, writes, unlocks, re-keys and changes passwords; the base56
textual identity (`SQRL::Textual`) carries the rescue-only blocks for manual entry.
