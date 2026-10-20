class User < ApplicationRecord
  has_many :sqrl_identities, class_name: "SQRL::Rails::Identity", as: :user, dependent: :destroy
  has_secure_password
  has_many :sessions, dependent: :destroy

  normalizes :email_address, with: ->(e) { e.strip.downcase }
end
