# frozen_string_literal: true

# Rails routing namespace, reopened to add +devise_sqrl+.
module ActionDispatch
  # Rails routing namespace.
  module Routing
    # Devise calls +devise_sqrl+ for every mapping whose model declares
    # +:sqrl_authenticatable+. The routes live under the mapping's path (+/users/sqrl+)
    # and get the helpers +new_user_sqrl_path+, +cli_user_sqrl_path+,
    # +status_user_sqrl_path+, +callback_user_sqrl_path+, +script_user_sqrl_path+,
    # +identities_user_sqrl_path+ and +unlink_identity_user_sqrl_path(id)+.
    class Mapper
      protected

      def devise_sqrl(mapping, controllers) # :nodoc:
        resource :sqrl, only: [], controller: controllers[:sqrl], path: mapping.path_names[:sqrl] do
          get :new, path: "", as: "new"
          post :cli
          get :status
          get :callback
          get :script, path: "sqrl.js"
          get :refresh
          get :identities
          delete "identities/:id", action: :unlink, as: :unlink_identity
        end
      end
    end
  end
end
