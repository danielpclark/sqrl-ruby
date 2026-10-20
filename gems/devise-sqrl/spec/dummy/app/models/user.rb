# frozen_string_literal: true

class User < ActiveRecord::Base
  devise :database_authenticatable, :rememberable, :trackable, :validatable, :sqrl_authenticatable

  # Simulates :confirmable style gating in specs.
  attr_accessor :inactive

  def active_for_authentication?
    super && !inactive
  end

  def inactive_message
    inactive ? :unconfirmed : super
  end
end
