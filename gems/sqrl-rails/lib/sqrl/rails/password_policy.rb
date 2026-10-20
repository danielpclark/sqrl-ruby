# frozen_string_literal: true

module SQRL
  module Rails
    # Enforces the two account-policy signals a SQRL client can send with +ident+:
    #
    # * +sqrlonly+ – "disable all non-SQRL authentication": password logins for the user
    #   must be refused ({Sessions}).
    # * +hardlock+ – "disable all non-SQRL account recovery": password resets for the
    #   user must be refused ({Passwords}).
    #
    # The concerns target the controllers that `bin/rails generate authentication`
    # produces (the generator adds the +include+ lines), but work in any controller that
    # takes an email address or a password-reset token:
    #
    #   class SessionsController < ApplicationController
    #     include SQRL::Rails::PasswordPolicy::Sessions      # before_action on :create
    #   end
    #
    #   class PasswordsController < ApplicationController
    #     include SQRL::Rails::PasswordPolicy::Passwords     # before_action on :create, :edit, :update
    #   end
    #
    # Override +sqrl_policy_user+ to change how the user is looked up, and
    # +sqrl_policy_refused(reason)+ to change the response (the default redirects to the
    # sign-in page with a flash alert from the +sqrl.password_policy+ translations).
    module PasswordPolicy
      # Shared lookup and response helpers.
      module Base
        extend ActiveSupport::Concern

        private

        # The user the current request is about: by +email_address+/+email+ parameter,
        # or by password-reset token when the request carries one.
        #
        # @return [Object, nil]
        def sqrl_policy_user
          return @user if instance_variable_defined?(:@user) && @user

          model = SQRL::Rails.config.user_model
          token = params[:token].presence
          if token
            found =
              if model.respond_to?(:find_by_password_reset_token)
                model.find_by_password_reset_token(token)
              elsif model.respond_to?(:find_by_token_for)
                model.find_by_token_for(:password_reset, token)
              end
            return found if found
          end
          email = params[:email_address].presence || params[:email].presence
          return nil if email.nil? || !model.respond_to?(:column_names)

          column = %w[email_address email].find { |c| model.column_names.include?(c) }
          column && model.find_by(column => email.to_s.strip.downcase)
        rescue StandardError
          nil
        end

        # Respond to a refused request. +reason+ is +:sqrl_only+ or +:hard_lock+.
        def sqrl_policy_refused(reason)
          message = I18n.t("sqrl.password_policy.#{reason}",
                           default: if reason == :sqrl_only
                                      "This account signs in with SQRL only."
                                    else
                                      "Password recovery is disabled for this account; use SQRL."
                                    end)
          flash[:alert] = message if respond_to?(:flash)
          target = sqrl_policy_redirect_path
          redirect_to target, allow_other_host: false
        end

        def sqrl_policy_redirect_path
          if respond_to?(:new_session_path, true)
            send(:new_session_path)
          elsif respond_to?(:root_path, true)
            send(:root_path)
          else
            "/"
          end
        end
      end

      # Refuses password logins for +sqrlonly+ users.
      module Sessions
        extend ActiveSupport::Concern
        include Base

        included do
          before_action :refuse_password_login_for_sqrl_only_users, only: :create
        end

        private

        def refuse_password_login_for_sqrl_only_users
          user = sqrl_policy_user
          sqrl_policy_refused(:sqrl_only) if user && SQRL::Rails.sqrl_only?(user)
        end
      end

      # Refuses password resets for +hardlock+ users.
      module Passwords
        extend ActiveSupport::Concern
        include Base

        included do
          before_action :refuse_password_reset_for_hard_locked_users, only: %i[create edit update]
        end

        private

        def refuse_password_reset_for_hard_locked_users
          user = sqrl_policy_user
          sqrl_policy_refused(:hard_lock) if user && SQRL::Rails.hard_locked?(user)
        end
      end
    end
  end
end
