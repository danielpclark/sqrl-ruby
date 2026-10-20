# frozen_string_literal: true

class User < ActiveRecord::Base
  has_secure_password validations: false
  # Rails 7.1 has generates_token_for but not the password_reset helpers of 7.2+.
  generates_token_for(:password_reset, expires_in: 15.minutes) { password_salt&.last(10) } unless method_defined?(:password_reset_token)
  has_many :sessions, dependent: :destroy
  has_many :sqrl_identities, class_name: "SQRL::Rails::Identity", as: :user, dependent: :destroy
end
