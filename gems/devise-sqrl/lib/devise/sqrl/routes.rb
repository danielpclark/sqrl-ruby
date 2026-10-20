# frozen_string_literal: true

module ActionDispatch
  module Routing
    # Devise calls +devise_sqrl+ for every mapping whose model declares
    # +:sqrl_authenticatable+. The routes live under the mapping's path (+/users/sqrl+)
    # and get the helpers +new_user_sqrl_path+, +cli_user_sqrl_path+,
    # +status_user_sqrl_path+, +callback_user_sqrl_path+ and +script_user_sqrl_path+.
    class Mapper
      protected

      def devise_sqrl(mapping, controllers) # :nodoc:
        resource :sqrl, only: [], controller: controllers[:sqrl], path: mapping.path_names[:sqrl] do
          get :new, path: "", as: "new"
          post :cli
          get :status
          get :callback
          get :script, path: "sqrl.js"
        end
      end
    end
  end
end
