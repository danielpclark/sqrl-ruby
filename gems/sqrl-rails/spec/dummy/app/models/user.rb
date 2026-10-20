# frozen_string_literal: true

class User < ActiveRecord::Base
  has_many :sessions, dependent: :destroy
  has_many :sqrl_identities, class_name: "SQRL::Rails::Identity", as: :user, dependent: :destroy
end
