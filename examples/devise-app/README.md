# Example: Devise + SQRL

A stock Rails 8.1 application generated with `rails new`, `bin/rails generate
devise:install` and `bin/rails generate devise User`, with SQRL login added by
`bin/rails generate devise:sqrl:install` from the `devise-sqrl` gem. Nothing else was
hand-written except the home page, a protected page and this file.

```sh
bundle install
bin/rails db:prepare
bin/dev                       # http://127.0.0.1:3000
```

Open <http://127.0.0.1:3000/users/sign_in>: Devise's email/password form now carries the
SQRL login block (link, QR code, status). Logging in with SQRL creates a `User` with a
placeholder email address and a random password (see
`config/initializers/devise_sqrl.rb` to change that policy) and signs it in through
Devise's Warden stack, so `current_user`, `user_signed_in?`, trackable and rememberable
all behave as with a password login.

Pages: `/` (home, shows the signed-in state), `/protected` (redirects anonymous visitors
to the sign-in page), `/users/sqrl` (SQRL-only login page). Log out with the "Log out"
button (`DELETE /users/sign_out`).

Environment variables: `PORT`, `BIND`, `SQRL_TLS_KEY`/`SQRL_TLS_CERT`, `SQRL_INSECURE_HTTP`, `SQRL_HOST` (public host for the `sqrl://` URLs),
`SQRL_ASK=1` (pose an "Allow this login?" question with Allow/Deny buttons; Deny refuses
the login), `SQRL_SIN=1` (send a secret-index challenge).

Routes added by Devise for `:sqrl_authenticatable`: `GET /users/sqrl`,
`POST /users/sqrl/cli` (protocol endpoint), `GET /users/sqrl/status`,
`GET /users/sqrl/callback`, `GET /users/sqrl/refresh`, `GET /users/sqrl/sqrl.js`,
`GET /users/sqrl/identities` (manage linked identities), `DELETE /users/sqrl/identities/:id`.

Account policies: a user whose SQRL client asked for `sqrlonly` cannot log in with a
password (Devise's password strategy is refused with "This account signs in with SQRL
only."), and one who asked for `hardlock` cannot request or perform a password reset.

## Logging in with the browser extension

Install the [SQRL Login extension](https://github.com/danielpclark/SQRL-extension) (Chrome
Web Store or Firefox Add-ons), create an identity, open the login page and click "Sign in
with SQRL". The extension needs either HTTPS (`SQRL_TLS_KEY`/`SQRL_TLS_CERT`; accept the
self-signed certificate in the browser once) or, on `localhost` only, `SQRL_INSECURE_HTTP=1`.

## TLS, `sqrl://` and plain http

SQRL login URLs are `sqrl://…` and always mean HTTPS, so a real SQRL client only works
when this app is served over TLS. `bin/dev` does that when `SQRL_TLS_KEY` and
`SQRL_TLS_CERT` point at a key and certificate (a self-signed one is fine locally; the
integration suite generates its own), or run it behind a TLS proxy. The integration specs
boot this app over HTTPS exactly that way.

`SQRL_INSECURE_HTTP=1` switches a loopback host to the non-standard `qrl://` (plain http)
form that GRC's early drafts defined and only the browser extension's local test flow still
accepts. It exists for that one purpose; it is not part of SQRL as specified and must never
be used outside local testing.
