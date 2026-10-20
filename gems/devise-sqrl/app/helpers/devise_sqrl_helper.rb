# frozen_string_literal: true

# View helpers for the SQRL login block of a Devise mapping.
module DeviseSQRLHelper
  # The complete SQRL login markup (link, QR code, status text and script tag) for a
  # Devise scope, wired to that scope's +/…/sqrl/*+ routes. Each render issues a fresh
  # login URL.
  #
  #   <%= sqrl_login_block_for(resource_name) %>
  #
  # @param resource_or_scope [Symbol, Object] +:user+, +resource_name+ or a record
  # @param return_to [String, nil] same-site path to land on after login
  # @param script [Boolean] append the +sqrl.js+ script tag
  # @param options [Hash] passed to +SQRL::Rack::LoginBlock.render+ (merged over
  #   +Devise.sqrl_login_block+)
  # @return [ActiveSupport::SafeBuffer]
  def sqrl_login_block_for(resource_or_scope, return_to: nil, script: true, **options)
    mapping = sqrl_devise_mapping(resource_or_scope)
    endpoint = Devise::SQRL.endpoint_for(mapping, request)
    login = sqrl_login_url_for(mapping.name, return_to: return_to)
    opts = Devise.sqrl_login_block.to_h.merge(options)
    ::SQRL::Rack::LoginBlock.render(login_url: login.url, status_url: endpoint.status_url(request),
                                    script_url: (endpoint.script_url(request) if script), **opts).html_safe # rubocop:disable Rails/OutputSafety
  end

  # The +sqrl://+ login URL issued for a scope (one per request per scope).
  #
  # @return [SQRL::Server::LoginURL]
  def sqrl_login_url_for(resource_or_scope, return_to: nil)
    mapping = sqrl_devise_mapping(resource_or_scope)
    @_devise_sqrl_logins ||= {}
    @_devise_sqrl_logins[mapping.name] ||= Devise::SQRL.endpoint_for(mapping, request)
                                                       .issue(request, return_to: sqrl_devise_return_to(return_to),
                                                                       link_user_ref: sqrl_devise_link_user_ref(mapping))
  end

  # +<script src="/users/sqrl/sqrl.js" defer>+ for a scope.
  def sqrl_script_tag_for(resource_or_scope)
    mapping = sqrl_devise_mapping(resource_or_scope)
    src = Devise::SQRL.endpoint_for(mapping, request).script_url(request)
    ::SQRL::Rack::LoginBlock.script_tag(src: src).html_safe # rubocop:disable Rails/OutputSafety
  end

  private

  def sqrl_devise_mapping(resource_or_scope)
    Devise.mappings.fetch(Devise::Mapping.find_scope!(resource_or_scope))
  end

  def sqrl_devise_return_to(explicit)
    candidate = explicit.presence || (params[:return_to].presence if respond_to?(:params))
    ::SQRL::Rails::SignIn.same_site_path?(candidate) ? candidate : nil
  rescue StandardError
    nil
  end

  def sqrl_devise_link_user_ref(mapping)
    return nil unless Devise::SQRL.on_unknown_identity == :link

    warden = request.env["warden"]
    current = warden&.user(mapping.name)
    current && ::SQRL::Rails.user_ref(current)
  rescue StandardError
    nil
  end
end
