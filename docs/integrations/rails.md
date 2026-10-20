# Rails and the Rails 8 authentication generator

Gem: `sqrl-rails`. Example: `examples/rails-auth-app` (Rails 8.1, `rails generate
authentication` followed by `rails generate sqrl:install`).

```sh
bundle add sqrl-rails
bin/rails generate sqrl:install
bin/rails db:migrate
```

The generator is idempotent and does five things: copies the migration for
`sqrl_identities`, `sqrl_nuts` and `sqrl_pending_logins`; mounts the engine at `/sqrl`;
writes `config/initializers/sqrl.rb`; adds `has_many :sqrl_identities` to `User`; and
appends `<%= sqrl_login_block %>` to `app/views/sessions/new.html.erb` when it exists.

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

## Operations

- `bin/rails sqrl:prune` deletes expired nuts and pending logins.
- Set `config.sqrl.host` in production. `config.sqrl.stores` defaults to ActiveRecord.
- The engine's `cli` action skips forgery protection; nothing else does.
