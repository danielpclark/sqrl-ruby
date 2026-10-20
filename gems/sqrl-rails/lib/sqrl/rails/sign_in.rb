# frozen_string_literal: true

module SQRL
  module Rails
    # The default sign-in adapter and redirect resolution.
    module SignIn
      SESSION_USER_KEY = :user_id
      SESSION_USER_TYPE_KEY = :sqrl_user_type

      module_function

      # Sign +user+ in on +controller+.
      #
      # 1. Rails' generated +Authentication+ concern: +start_new_session_for(user)+.
      # 2. Warden (if the app uses it directly): +warden.set_user(user)+.
      # 3. Fallback: +session[:user_id]+ (and the user's class name).
      def default(controller, _identity, user)
        if controller.respond_to?(:start_new_session_for, true)
          controller.send(:start_new_session_for, user)
        elsif controller.request.env["warden"].respond_to?(:set_user)
          controller.request.env["warden"].set_user(user)
        else
          controller.session[SESSION_USER_KEY] = user.id
          controller.session[SESSION_USER_TYPE_KEY] = user.class.name
        end
      end

      # The user signed in through {default}'s fallback, for applications without their
      # own +current_user+.
      def session_user(session)
        id = session[SESSION_USER_KEY]
        return nil if id.nil?

        klass = session[SESSION_USER_TYPE_KEY].presence&.safe_constantize || SQRL::Rails.config.user_model
        klass.find_by(klass.primary_key => id)
      end

      # Where to go after a successful login.
      def after(controller, completion)
        return_to = completion.return_to
        return return_to if same_site_path?(return_to)

        custom = SQRL::Rails.config.after_sign_in
        return custom.call(controller, completion) if custom

        if controller.respond_to?(:after_authentication_url, true)
          controller.send(:after_authentication_url)
        elsif controller.respond_to?(:main_app) && controller.main_app.respond_to?(:root_path)
          controller.main_app.root_path
        else
          "/"
        end
      end

      # The signed-in user for linking purposes.
      def current_user(controller)
        custom = SQRL::Rails.config.current_user
        return custom.call(controller) if custom

        if Object.const_defined?(:Current) && ::Current.respond_to?(:user)
          controller.send(:resume_session) if controller.respond_to?(:resume_session, true)
          user = ::Current.user
          return user if user
        end
        session_user(controller.session)
      rescue StandardError
        nil
      end

      def same_site_path?(path)
        path.is_a?(String) && path.start_with?("/") && !path.start_with?("//")
      end
    end
  end
end
