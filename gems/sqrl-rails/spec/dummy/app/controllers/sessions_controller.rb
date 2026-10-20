# frozen_string_literal: true

class SessionsController < ApplicationController
  include SQRL::Rails::PasswordPolicy::Sessions

  allow_unauthenticated_access only: %i[new create]
  protect_from_forgery except: %i[create destroy] # the spec posts without a form token

  def new
  end

  # A copy of the Rails 8 generated password login.
  def create
    if (user = User.authenticate_by(params.permit(:email_address, :password)))
      start_new_session_for user
      redirect_to after_authentication_url
    else
      redirect_to new_session_path, alert: "Try another email address or password."
    end
  end

  def destroy
    terminate_session
    sqrl_logout!
    redirect_to new_session_path, status: :see_other
  end
end
