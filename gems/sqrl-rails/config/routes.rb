# frozen_string_literal: true

SQRL::Rails::Engine.routes.draw do
  post "cli", to: "cli#create", as: :cli
  get "status", to: "status#show", as: :status
  get "callback", to: "callback#show", as: :callback
  get "login", to: "logins#new", as: :login
  get "sqrl.js", to: "assets#script", as: :script
  get "refresh", to: "refresh#show", as: :refresh
  get "identities", to: "identities#index", as: :identities
  delete "identities/:id", to: "identities#destroy", as: :identity_unlink
end
