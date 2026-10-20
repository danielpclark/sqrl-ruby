# frozen_string_literal: true

# The SQRL routes of a Devise mapping: the login page, the protocol endpoint, the
# cookie-bound status poll, the login callback and the browser script.
#
# Override it like any Devise controller:
#
#   devise_for :users, controllers: { sqrl: "users/sqrl" }
class Devise::SQRLController < DeviseController
  # The protocol endpoint is authenticated by SQRL's own signatures; the client is not a
  # browser and carries no CSRF token.
  skip_forgery_protection only: %i[cli script]
  # Polls and protocol requests must not count as user activity for :timeoutable.
  prepend_before_action(only: %i[cli status script refresh]) { request.env["devise.skip_timeout"] = true }

  # A before_issue / before_handle hook refused the request.
  rescue_from ::SQRL::Server::RateLimited do |error|
    render_sqrl_rack(sqrl_endpoint.rate_limited(error, json: request.format.json?))
  end

  # The request host may not be used to issue SQRL URLs.
  rescue_from ::SQRL::Rack::HostNotAllowed do |error|
    render plain: error.message, status: :bad_request
  end
  # Identity management is for the signed-in resource of this scope.
  prepend_before_action :authenticate_scope!, only: %i[identities unlink]

  # GET /users/sqrl : a stand-alone SQRL login page (the view issues the login URL
  # through +sqrl_login_block_for+; the JSON form issues it here).
  def new
    respond_to do |format|
      format.html
      format.json do
        login = sqrl_login_url_for(resource_name, return_to: sqrl_return_to)
        render json: { url: login.url, nut: login.nut, status: sqrl_endpoint.status_url(request),
                       callback: sqrl_endpoint.callback_url(request) }
      end
    end
  end

  # POST /users/sqrl/cli : the SQRL client's signed requests.
  def cli
    render_sqrl_rack(sqrl_endpoint.cli(request))
  end

  # GET /users/sqrl/status : {"authenticated": bool, "next": url}
  def status
    render_sqrl_rack(sqrl_endpoint.status(request))
  end

  # GET /users/sqrl/refresh : a fresh login URL for this browser session, as JSON.
  def refresh
    render_sqrl_rack(sqrl_endpoint.refresh(request))
  end

  # GET /users/sqrl/sqrl.js
  def script
    status, headers, body = sqrl_endpoint.script(request)
    headers.each { |k, v| response.set_header(k, v) }
    if status == 304
      head :not_modified
    else
      render body: body.join, status: status, content_type: "application/javascript"
    end
  end

  # GET /users/sqrl/callback[?t=TOKEN] : completes the login through the
  # :sqrl_authenticatable Warden strategy and signs the resource in like Devise's
  # sessions controller does. The strategy is run explicitly (not through
  # +warden.authenticate!+) so that the one-time token is verified even when this
  # browser already has a signed-in user, for example when linking a second identity.
  def callback
    strategy = Warden::Strategies[:sqrl_authenticatable].new(request.env, resource_name)
    strategy._run!
    return failure(strategy.message || :sqrl_invalid) unless strategy.successful?

    self.resource = strategy.user
    completion = request.env["devise.sqrl.completion"]
    return_to = completion&.return_to
    store_location_for(resource_name, return_to) if same_site_path?(return_to)
    set_flash_message!(:notice, :signed_in)
    sign_in_and_redirect(resource_name, resource, event: :authentication)
  end

  # GET /users/sqrl/identities : the SQRL identities linked to the signed-in resource.
  def identities
    @identities = resource.sqrl_identities.order(:created_at)
    @current_idk = sqrl_endpoint.current_identity(request)&.idk_b64
  end

  # DELETE /users/sqrl/identities/:id : detach one identity from the signed-in resource.
  # The site keeps the protocol association; the next login with that identity is
  # treated as an unknown identity again.
  def unlink
    identity = resource.sqrl_identities.find_by(id: params[:id])
    if identity
      current = sqrl_endpoint.current_identity(request)&.idk_b64
      resource.unlink_sqrl_identity!(identity)
      sqrl_endpoint.logout(request) if current && current == identity.idk
      set_flash_message!(:notice, :identity_unlinked)
    else
      set_flash_message!(:alert, :identity_not_found)
    end
    redirect_to identities_sqrl_path(resource_name), status: :see_other
  end

  protected

  # Like Devise's registrations controller: the signed-in resource of this scope.
  def authenticate_scope!
    send(:"authenticate_#{resource_name}!", force: true)
    self.resource = send(:"current_#{resource_name}")
  end

  # Redirect to the SQRL login page (or +Devise.sqrl_failure_path+) with the reason.
  def failure(reason)
    message = reason.is_a?(Symbol) ? I18n.t("devise.failure.#{reason}", default: reason.to_s.humanize) : reason.to_s
    flash[:alert] = message if is_flashing_format?
    redirect_to sqrl_failure_path, allow_other_host: false
  end

  def sqrl_endpoint
    @sqrl_endpoint ||= Devise::SQRL.endpoint_for(devise_mapping, request)
  end

  def sqrl_failure_path
    Devise.sqrl_failure_path || new_sqrl_path(resource_name)
  end

  def sqrl_return_to
    candidate = params[:return_to].presence
    same_site_path?(candidate) ? candidate : nil
  end

  # The signed-in resource a new identity may be linked to (policy :link).
  def sqrl_link_user_ref
    return nil unless Devise::SQRL.on_unknown_identity == :link

    current = warden.user(resource_name)
    current && ::SQRL::Rails.user_ref(current)
  end

  def same_site_path?(path)
    ::SQRL::Rails::SignIn.same_site_path?(path)
  end

  def render_sqrl_rack(triple)
    status, headers, body = triple
    headers.each { |k, v| response.set_header(k, v) }
    render body: body.join, status: status, content_type: headers["content-type"]
  end

  def translation_scope
    "devise.sqrl"
  end

  include DeviseSQRLHelper
end
