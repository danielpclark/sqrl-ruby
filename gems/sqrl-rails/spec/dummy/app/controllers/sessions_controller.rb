# frozen_string_literal: true

class SessionsController < ApplicationController
  allow_unauthenticated_access only: :new
  protect_from_forgery except: :destroy # the spec logs out without a form token

  def new
  end

  def destroy
    terminate_session
    sqrl_logout!
    redirect_to new_session_path, status: :see_other
  end
end
