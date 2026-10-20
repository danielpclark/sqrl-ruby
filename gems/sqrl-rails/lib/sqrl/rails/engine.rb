# frozen_string_literal: true

# The engine's app/ directories are namespaced SQRL::Rails; teach the inflector the acronym
# so Zeitwerk maps app/models/sqrl/rails/identity.rb to SQRL::Rails::Identity.
ActiveSupport::Inflector.inflections(:en) { |inflect| inflect.acronym "SQRL" }

module SQRL
  module Rails
    # The Rails engine. Mount it in the host application:
    #
    #   mount SQRL::Rails::Engine, at: "/sqrl", as: :sqrl
    #
    # It serves +POST /sqrl/cli+ (the SQRL endpoint), +GET /sqrl/status+ (cookie-bound
    # poll), +GET /sqrl/callback+ (login completion), +GET /sqrl/login+ (a stand-alone
    # login page) and +GET /sqrl/sqrl.js+.
    class Engine < ::Rails::Engine
      isolate_namespace SQRL::Rails
      engine_name "sqrl"

      config.sqrl = Configuration.new

      initializer "sqrl.helpers" do
        ActiveSupport.on_load(:action_controller_base) do
          include SQRL::Rails::ControllerHelpers

          helper SQRL::Rails::LoginHelper
        end
        ActiveSupport.on_load(:action_view) do
          include SQRL::Rails::LoginHelper
        end
      end

      initializer "sqrl.reset_on_reload" do |app|
        app.reloader.to_prepare { SQRL::Rails.reset! } if app.respond_to?(:reloader)
      end

      rake_tasks do
        load File.expand_path("../../tasks/sqrl.rake", __dir__)
      end
    end
  end
end
