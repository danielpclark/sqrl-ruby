class HomeController < ApplicationController
  allow_unauthenticated_access only: :index

  def index
    resume_session
  end

  def protected
  end
end
