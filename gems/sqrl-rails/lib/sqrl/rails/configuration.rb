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
      SERVER_OPTIONS = %i[insecure_http path_extension nut_ttl cps_token_ttl require_ip_match ask sin
                          on_unknown_identity on_authenticated cps_url clock logger allowed_hosts prune_every
                          before_issue before_handle].freeze

      # --- protocol (see SQRL::Server::Config) ---------------------------------------
      # Public host (with port when not default) for issued +sqrl://+ URLs. Defaults to
      # the request's host.
      attr_accessor :host
      # Always +"sqrl"+ (HTTPS). Leave nil; set +insecure_http+ for the testing mode.
      attr_accessor :scheme
      # Loopback-only testing mode issuing +qrl://+ (plain http) URLs, for example to try
      # the browser extension against +bin/rails server+ without TLS. +qrl://+ is not part
      # of the final SQRL specification; real clients require +sqrl://+ over HTTPS.
      attr_accessor :insecure_http
      # Optional hardening (default false): a login completed through the browser's own
      # cookie (the poll path) counts only when the SQRL client's IP matched the
      # browser's. It also refuses legitimate logins from a phone on another network.
      attr_accessor :poll_requires_ip_match
      attr_accessor :path_extension, :nut_ttl, :cps_token_ttl, :require_ip_match, :ask, :sin, :on_unknown_identity, :on_authenticated, :cps_url,
                    :clock, :logger, :session_key, :identity_key
      # Hosts (Strings or Regexps) a request may use when +host+ is not configured.
      attr_accessor :allowed_hosts
      # Maximum number of distinct derived request hosts kept per process (default 16).
      attr_accessor :host_cache_limit
      # Delete expired nuts and pending logins after every N handled requests (default
      # 1000; nil disables opportunistic pruning).
      attr_accessor :prune_every
      # Callables +(context)+ run before a login URL is issued / before a protocol request
      # is handled; raise +SQRL::Server::RateLimited+ to refuse (answered with 429).
      attr_accessor :before_issue, :before_handle

      # When the site poses an +ask+ (see +ask+), the number of the button that means
      # "do not log me in" (buttons are numbered from 1). A login completed with that
      # answer is refused at the callback. +nil+ accepts every answer.
      attr_accessor :ask_deny_button

      # --- storage ---------------------------------------------------------------------
      # +:active_record+ (default), +:cache+ (see +cache_store+), +:memory+, or an
      # +SQRL::Server::Stores+.
      attr_accessor :stores
      # The +ActiveSupport::Cache::Store+ used by +stores = :cache+ (default +Rails.cache+).
      # It must delete atomically (Redis, Memcached); see {Stores::Cache}.
      attr_accessor :cache_store

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
      # Callable +(request) -> String+ resolving the client IP (default +remote_ip+).
      attr_accessor :ip
      # Rate limit for the protocol endpoint and the login page, as
      # +{ to: 60, within: 1.minute }+ (per client IP, counted in +Rails.cache+); +nil+
      # disables it. Optional keys: +by:+ a callable +(request) -> String+, +cache:+ a
      # cache store, +only:+ an array of +:cli+, +:login+, +:status+, +:callback+.
      attr_accessor :rate_limit

      def initialize
        @host = nil
        @scheme = nil
        @insecure_http = false
        @poll_requires_ip_match = false
        @path_extension = nil
        @nut_ttl = 300
        @cps_token_ttl = 60
        @require_ip_match = true
        @ask = nil
        @sin = nil
        @ask_deny_button = nil
        @allowed_hosts = nil
        @host_cache_limit = nil
        @prune_every = nil
        @before_issue = nil
        @before_handle = nil
        @on_unknown_identity = :create
        @on_authenticated = nil
        @cps_url = nil
        @clock = nil
        @logger = nil
        @stores = :active_record
        @cache_store = nil
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
        @rate_limit = nil
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
