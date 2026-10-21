# Rails and the Rails 8 authentication generator

Gem: `sqrl-rails`. Example: `examples/rails-auth-app` (Rails 8.1, `rails generate
authentication` followed by `rails generate sqrl:install`).

```sh
bundle add sqrl-rails
bin/rails generate sqrl:install
bin/rails db:migrate
```

The generator is idempotent and does six things: copies the migration for
`sqrl_identities`, `sqrl_nuts` and `sqrl_pending_logins`; mounts the engine at `/sqrl`;
writes `config/initializers/sqrl.rb`; adds `has_many :sqrl_identities` to `User`; includes
the `sqrlonly`/`hardlock` password policies in the generated `SessionsController` and
`PasswordsController`; and appends `<%= sqrl_login_block %>` to
`app/views/sessions/new.html.erb` when it exists.

The engine serves `POST /sqrl/cli`, `GET /sqrl/status`, `GET /sqrl/callback`,
`GET /sqrl/refresh`, `GET /sqrl/sqrl.js`, a stand-alone `GET /sqrl/login` page and
`GET /sqrl/identities` (list and unlink the signed-in user's identities).

## Rails 8 `Authentication` concern

Nothing to configure. When the generated `Authentication` concern exists, the engine's
callback controller includes it, allows unauthenticated access to itself, and signs the
user in with `start_new_session_for(user)`, so a `Session` row is created with the
browser's IP and user agent exactly as a password login would. The redirect target is the
pending login's `return_to`, then `after_authentication_url`, then root.

## Other session schemes

```ruby
Rails.application.config.sqrl.sign_in = ->(controller, identity, user) { controller.session[:uid] = user.id }
Rails.application.config.sqrl.after_sign_in = ->(controller, completion) { controller.main_app.root_path }
```

Without a custom adapter the engine falls back to Warden (`warden.set_user`) when present,
and otherwise to `session[:user_id]`.

## Unknown identities

`on_unknown_identity` is `:create` by default: `SQRL::Rails::UserFactory` builds a user,
filling placeholder `email`/`email_address`, `name`/`username` and a random password only
when those columns or writers exist. Replace it with `config.sqrl.create_user` when your
model needs more. `:link` attaches the new identity to `Current.user` (or
`config.sqrl.current_user`); `:refuse` rejects it.

## Account policies

`SQRL::Rails.sqrl_only?(user)` and `hard_locked?(user)` report what the user's SQRL client
asked for. `SQRL::Rails::PasswordPolicy::Sessions` refuses password login for `sqrlonly`
users and `PasswordPolicy::Passwords` refuses password reset for `hardlock` users; the
generator includes both in the Rails 8 generated controllers.

## Operations

- `bin/rails sqrl:prune` deletes expired nuts and pending logins; `config.sqrl.prune_every`
  does it opportunistically.
- Set `config.sqrl.host` in production (or `allowed_hosts` when it must be derived).
  `config.sqrl.stores` is `:active_record` by default, or `:cache` for an
  `ActiveSupport::Cache` store with atomic delete, or `:memory` for development.
- `config.sqrl.rate_limit = { to: 60, within: 1.minute }` throttles the SQRL routes per
  client IP; `before_issue` / `before_handle` hooks may raise `SQRL::Server::RateLimited`.
- The engine's `cli` action skips forgery protection; nothing else does.
- `insecure_http` (loopback-only plain HTTP) and `poll_requires_ip_match` (off by default)
  behave as described in [docs/security.md](../security.md).

The [gem README](../../gems/sqrl-rails/README.md) has the full option table.
