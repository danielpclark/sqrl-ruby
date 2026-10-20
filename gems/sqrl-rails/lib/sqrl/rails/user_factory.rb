# frozen_string_literal: true

require "securerandom"

module SQRL
  module Rails
    # Default +create_user+: builds a user record for a brand-new SQRL identity using
    # only the columns the model has. SQRL carries no profile data, so placeholders are
    # generated: a random password when the model has +password_digest+ (so
    # +has_secure_password+ validations pass) and a non-routable email when it has an
    # +email+ or +email_address+ column. Applications that need real data set
    # +config.sqrl.create_user+ or use +on_unknown_identity = :link+.
    module UserFactory
      module_function

      # @param identity [SQRL::Server::Identity]
      # @param model [Class] the user model
      # @return [Object] the saved user
      def call(identity, model = SQRL::Rails.config.user_model)
        model.create!(attributes_for(identity, model))
      end

      # @return [Hash] placeholder attributes matching the columns and writers the user model has
      def attributes_for(identity, model)
        columns = model.respond_to?(:column_names) ? model.column_names : []
        handle = identity.idk_b64[0, 16].downcase.tr("_-", "xy")
        attrs = {}
        attrs[:email_address] = "sqrl-#{handle}@sqrl.invalid" if columns.include?("email_address")
        attrs[:email] = "sqrl-#{handle}@sqrl.invalid" if columns.include?("email")
        attrs[:name] = "SQRL user #{handle[0, 8]}" if columns.include?("name")
        attrs[:username] = "sqrl-#{handle}" if columns.include?("username")
        if model.method_defined?(:password=)
          password = SecureRandom.hex(32)
          attrs[:password] = password
          attrs[:password_confirmation] = password if model.method_defined?(:password_confirmation=)
        end
        attrs
      end
    end
  end
end
