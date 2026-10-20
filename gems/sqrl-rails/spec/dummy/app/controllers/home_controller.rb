# frozen_string_literal: true

class HomeController < ApplicationController
  allow_unauthenticated_access only: :index

  def index
    resume_session
    render plain: Current.user ? "home: #{Current.user.name}" : "home: anonymous"
  end

  def protected
    render plain: "protected: #{Current.user.name}"
  end
end
