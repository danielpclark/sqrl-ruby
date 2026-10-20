# Example: Rails 8 built-in authentication + SQRL

A stock Rails 8.1 application generated with `rails new` and `bin/rails generate
authentication`, with SQRL login added by `bin/rails generate sqrl:install` from the
`sqrl-rails` gem. Nothing else was hand-written except the home page, a protected page
and this file.

```sh
bundle install
bin/rails db:prepare
bin/dev                       # http://127.0.0.1:3000
```

Open <http://127.0.0.1:3000/session/new>: the generated email/password form now carries
the SQRL login block (link, QR code, status). Logging in with SQRL creates a `User` with a
placeholder email address and a random password (see `config/initializers/sqrl.rb` to
change that policy), starts a Rails `Session` exactly as the password form would, and
redirects to the page you came from.

Environment variables: `PORT`, `BIND`, `SQRL_HOST` (public host for the `sqrl://` URLs),
`SQRL_ASK=1` (pose an "Allow this login?" question with Allow/Deny buttons; Deny refuses
the login), `SQRL_SIN=1` (send a secret-index challenge).

Useful routes: `/sqrl/login` (stand-alone SQRL page), `POST /sqrl/cli` (protocol
endpoint), `/sqrl/status`, `/sqrl/callback`, `/sqrl/sqrl.js`, `/sqrl/identities`
(the signed-in user's SQRL identities, with an Unlink button).

Account policies: the generator added `SQRL::Rails::PasswordPolicy::Sessions` to
`SessionsController` and `::Passwords` to `PasswordsController`, so a user whose SQRL
client asked for `sqrlonly` cannot log in with a password, and one who asked for
`hardlock` cannot reset it.
