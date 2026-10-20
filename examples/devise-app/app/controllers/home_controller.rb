class HomeController < ApplicationController
  # Anonymous visitors are redirected to /users/sign_in by Devise.
  before_action :authenticate_user!, only: :protected

  def index
  end

  def protected
  end
end
