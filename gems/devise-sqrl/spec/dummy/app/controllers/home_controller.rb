# frozen_string_literal: true

class HomeController < ApplicationController
  before_action :authenticate_user!, only: :protected
  skip_forgery_protection only: :logout

  def index
    render plain: user_signed_in? ? "home: #{current_user.email}" : "home: anonymous"
  end

  def protected
    render plain: "protected: #{current_user.email}"
  end

  def logout
    sign_out(:user)
    head :no_content
  end
end
