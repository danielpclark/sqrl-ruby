# frozen_string_literal: true

Rails.application.routes.draw do
  devise_for :users
  root "home#index"
  get "protected", to: "home#protected"
  delete "logout", to: "home#logout"
end
