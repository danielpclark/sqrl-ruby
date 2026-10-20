# frozen_string_literal: true

# A trimmed copy of the Rails 8 generated password-reset controller.
class PasswordsController < ApplicationController
  include SQRL::Rails::PasswordPolicy::Passwords

  allow_unauthenticated_access
  protect_from_forgery except: %i[create update]
  before_action :set_user_by_token, only: %i[edit update]

  def new
    render plain: "reset form"
  end

  def create
    render plain: "reset mail sent"
  end

  def edit
    render plain: "edit form for #{@user.email_address}"
  end

  def update
    @user.update!(password: params[:password])
    render plain: "password reset"
  end

  private

  def set_user_by_token
    @user = User.find_by_token_for!(:password_reset, params[:token])
  rescue ActiveSupport::MessageVerifier::InvalidSignature, ActiveRecord::RecordNotFound
    redirect_to new_password_path, alert: "Password reset link is invalid or has expired."
  end
end
