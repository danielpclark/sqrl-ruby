# frozen_string_literal: true

module SQRL
  module Rails
    # +Rails.application.config.sqrl+. Every {SQRL::Server::Config} option is available,
    # plus the Rails-specific settings that map a SQRL identity to a user and a user to a
    # signed-in session.
    #
    #   Rails.application.config.sqrl.tap do |sqrl|
    #     sqrl.host = "example.com"           # public host placed in sqrl:// URLs (default: request host)
    #     sqrl.on_unknown_identity = :create  # :create, :link or :refuse
    #     sqrl.sign_in = ->(controller, identity, user) { controller.send(:start_new_session_for, user) }
    #   end
    class Configuration
      SERVER_OPTIONS = %i[path_extension nut_ttl cps_token_ttl require_ip_match ask sin on_unknown_identity
                          on_authenticated cps_url clock logger].freeze

      # --- protocol (see SQRL::Server::Config) ---------------------------------------
      # Public host (with port when not default) for issued +sqrl://+ URLs. Defaults to
      # the request's host.
      attr_accessor :host
      # +"sqrl"+ or +"qrl"+; nil picks +qrl+ for plain-http loopback requests.
      attr_accessor :scheme
      attr_accessor :path_extension, :nut_ttl, :cps_token_ttl, :require_ip_match, :ask, :sin,
                    :on_unknown_identity, :on_authenticated, :cps_url, :clock, :logger

      # --- storage ---------------------------------------------------------------------
      # +:active_record+ (default), +:memory+, or an +SQRL::Server::Stores+.
      attr_accessor :stores

      # --- users -----------------------------------------------------------------------
      # Name of the user model (+"User"+).
      attr_accessor :user_class
      # Callable +(identity) -> user or nil+ resolving the record an identity belongs to.
      attr_accessor :find_user
      # Callable +(identity) -> user+ creating a user for a brand-new identity
      # (+on_unknown_identity = :create+). Defaults to {UserFactory}.
      attr_accessor :create_user
      # Callable +(controller) -> user or nil+ giving the signed-in user, used to link new
      # identities (+:link+). Defaults to +Current.user+ when the host defines it.
      attr_accessor :current_user
      # Callable +(controller, identity, user)+ that signs the user in. Defaults to
      # {SignIn.default}: +start_new_session_for+ from Rails' generated
      # +Authentication+ concern when present, otherwise +session[:user_id]+.
      attr_accessor :sign_in
      # Callable +(controller, completion) -> String+ giving the redirect target after
      # sign-in; a same-site +return_to+ recorded on the pending login wins.
      attr_accessor :after_sign_in
      # Where to send the browser when the callback cannot complete a login.
      attr_accessor :failure_path

      # --- plumbing --------------------------------------------------------------------
      # Mount path of the engine; auto-detected from the routes when nil.
      attr_accessor :mount_path
      attr_accessor :session_key, :identity_key
      # Callable +(request) -> String+ resolving the client IP (default +remote_ip+).
      attr_accessor :ip

      def initialize
        @host = nil
        @scheme = nil
        @path_extension = nil
        @nut_ttl = 300
        @cps_token_ttl = 60
        @require_ip_match = true
        @ask = nil
        @sin = nil
        @on_unknown_identity = :create
        @on_authenticated = nil
        @cps_url = nil
        @clock = nil
        @logger = nil
        @stores = :active_record
        @user_class = "User"
        @find_user = nil
        @create_user = nil
        @current_user = nil
        @sign_in = nil
        @after_sign_in = nil
        @failure_path = nil
        @mount_path = nil
        @session_key = SQRL::Rack::Endpoint::SESSION_KEY
        @identity_key = SQRL::Rack::Endpoint::IDENTITY_KEY
        @ip = nil
      end

      # Keyword options for {SQRL::Server::Config} (host, scheme and paths are added by
      # the engine per request).
      def server_options
        SERVER_OPTIONS.each_with_object({}) do |key, opts|
          value = public_send(key)
          opts[key] = value unless value.nil?
        end
      end

      # The user model class.
      def user_model
        user_class.is_a?(Class) ? user_class : user_class.to_s.constantize
      end
    end
  end
end
