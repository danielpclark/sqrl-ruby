# frozen_string_literal: true

# Enforces +sqrlonly+: a record whose SQRL identity asked the site to refuse non-SQRL
# authentication is not allowed to sign in through a password strategy. The hook runs
# like Devise's own activatable hook, after Warden set the user, and only when the
# login came through one of +Devise.sqrl_only_blocked_strategies+ (the password
# strategy by default). SQRL logins, remember-me cookies and sessions restored from the
# cookie are untouched.
Warden::Manager.after_set_user except: :fetch do |record, warden, options|
  if record.respond_to?(:sqrl_only?) && Devise::SQRL.blocked_strategy?(warden.winning_strategy) && record.sqrl_only?
    scope = options[:scope]
    warden.logout(scope)
    throw :warden, scope: scope, message: :sqrl_only
  end
end
