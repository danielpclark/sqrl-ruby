# frozen_string_literal: true

module Devise
  module Models
    # Adds SQRL login to a Devise model.
    #
    #   class User < ApplicationRecord
    #     devise :database_authenticatable, :sqrl_authenticatable
    #   end
    #
    # The model gets +sqrl_identities+ (rows of the +sqrl_identities+ table from the
    # sqrl-rails migration) and the lookup and linking methods the
    # +:sqrl_authenticatable+ strategy relies on. No columns are needed on the model.
    module SQRLAuthenticatable
      extend ActiveSupport::Concern

      included do
        if respond_to?(:has_many)
          has_many :sqrl_identities, -> { where(superseded_by: nil) },
                   class_name: "SQRL::Rails::Identity", as: :user, dependent: :destroy
        end
      end

      def self.required_fields(_klass)
        []
      end

      # The SQRL identity record (+SQRL::Rails::Identity+) for an identity key, or nil.
      #
      # @param idk [String] base64url identity key
      def sqrl_identity_for(idk)
        sqrl_identities.find_by(idk: idk)
      end

      # Whether at least one SQRL identity is attached.
      def sqrl_linked?
        sqrl_identities.exists?
      end

      # Attach an identity (an +SQRL::Server::Identity+ from the protocol handler, an
      # +SQRL::Rails::Identity+ row, or a base64url idk) to this record.
      def link_sqrl_identity!(identity)
        ::SQRL::Rails.stores.identities.update(sqrl_identity_idk_bytes(identity), user_ref: ::SQRL::Rails.user_ref(self))
        self
      end

      # Detach an identity from this record (the site association stays; the identity can
      # no longer sign in as this user).
      def unlink_sqrl_identity!(identity)
        row = sqrl_identity_for(sqrl_identity_idk_b64(identity))
        row&.update!(user: nil)
        self
      end

      private

      def sqrl_identity_idk_b64(identity)
        case identity
        when String then identity
        when ::SQRL::Rails::Identity then identity.idk
        else identity.idk_b64
        end
      end

      def sqrl_identity_idk_bytes(identity)
        ::SQRL::Util.b64u_decode(sqrl_identity_idk_b64(identity))
      end

      module ClassMethods
        # The record a SQRL identity belongs to, when it belongs to this model.
        #
        # @param identity [SQRL::Server::Identity]
        # @return [Object, nil]
        def find_for_sqrl(identity)
          user = ::SQRL::Rails.user_from_ref(identity.user_ref)
          return user if user.is_a?(self)

          row = ::SQRL::Rails::Identity.active.find_by(idk: identity.idk_b64)
          owner = row&.user
          owner.is_a?(self) ? owner : nil
        end

        # Create a record for a brand-new identity and attach the identity to it.
        #
        # @param identity [SQRL::Server::Identity]
        # @return [Object] the saved record
        def create_for_sqrl!(identity)
          factory = Devise.sqrl_create_resource
          resource = factory ? factory.call(identity, self) : ::SQRL::Rails::UserFactory.call(identity, self)
          raise Devise::SQRL::Error, "sqrl_create_resource returned no record" unless resource

          resource.save! if resource.respond_to?(:new_record?) && resource.new_record?
          resource.link_sqrl_identity!(identity)
          resource
        end
      end
    end
  end
end
