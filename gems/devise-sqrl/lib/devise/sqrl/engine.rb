# frozen_string_literal: true

module Devise
  module SQRL
    # Loads the controller, views, helper and translations into the host application.
    class Engine < ::Rails::Engine
      engine_name "devise_sqrl"

      initializer "devise_sqrl.helpers" do
        ActiveSupport.on_load(:action_controller_base) do
          helper DeviseSQRLHelper
        end
        ActiveSupport.on_load(:action_view) do
          include DeviseSQRLHelper
        end
      end

      initializer "devise_sqrl.reset_on_reload" do |app|
        app.reloader.to_prepare { Devise::SQRL.reset! } if app.respond_to?(:reloader)
      end
    end
  end
end
