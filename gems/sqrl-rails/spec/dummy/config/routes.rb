# frozen_string_literal: true

Rails.application.routes.draw do
  root "home#index"
  get "protected", to: "home#protected"
  resource :session, only: %i[new destroy]
  mount SQRL::Rails::Engine, at: "/sqrl", as: :sqrl
end
