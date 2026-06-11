/*
 * Copyright 2026 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.keycloak.broker;

import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.models.KeycloakSession;

/**
 * OIDC identity provider that forwards {@code kc_idp_hint} from the broker button-click URL to the
 * upstream realm's authorization request.
 *
 * <p>Keycloak's built-in {@code forwardParameters} mechanism reads {@code kc_idp_hint} from the
 * authentication-session notes, which are populated from the <em>initial</em> client authorization
 * request. In a two-realm brokering chain (orgiam → Transient → SAML IdP) the initial request from
 * the application does not carry {@code kc_idp_hint}; instead the hint is appended to the broker
 * login URL by the custom {@code login.ftl} when the user clicks an IdP button. This provider
 * complements the session-note path by also reading {@code kc_idp_hint} directly from the current
 * HTTP request query parameters, so the hint reaches the Transient realm's authorization endpoint.</p>
 *
 * @author David Goldring
 */
public class IdpHintOidcIdentityProvider extends OIDCIdentityProvider {

  private static final Logger log = Logger.getLogger(IdpHintOidcIdentityProvider.class);

  /** The query parameter name this provider forwards. */
  public static final String KC_IDP_HINT = "kc_idp_hint";

  /**
   * Creates a new provider instance.
   *
   * @param session the Keycloak session
   * @param config the OIDC identity provider configuration
   */
  public IdpHintOidcIdentityProvider(
      final KeycloakSession session, final OIDCIdentityProviderConfig config) {
    super(session, config);
  }

  /**
   * Builds the upstream authorization URL, adding {@code kc_idp_hint} from the current HTTP
   * request when present.
   *
   * @param request the authentication request context
   * @return the authorization URL builder, with {@code kc_idp_hint} appended if supplied
   */
  @Override
  protected UriBuilder createAuthorizationUrl(final AuthenticationRequest request) {
    final UriBuilder uriBuilder = super.createAuthorizationUrl(request);
    return this.appendIdpHintParam(uriBuilder, request);
  }

  /**
   * Appends {@code kc_idp_hint} to the upstream authorization URL when the current HTTP request
   * carries the parameter.
   *
   * <p>Extracted as a {@code protected} method to allow unit testing without depending on the
   * full {@link org.keycloak.broker.oidc.OIDCIdentityProvider} base-class constructor chain.</p>
   *
   * @param uriBuilder the base authorization URL builder returned by the super implementation
   * @param request the current authentication request
   * @return the same builder, with {@code kc_idp_hint} appended when present and non-blank
   */
  protected UriBuilder appendIdpHintParam(
      final UriBuilder uriBuilder, final AuthenticationRequest request) {
    final String hint = request.getHttpRequest().getUri()
        .getQueryParameters().getFirst(KC_IDP_HINT);
    if (hint != null && !hint.isBlank()) {
      log.debugf("Forwarding %s=%s to upstream IdP %s", KC_IDP_HINT, hint, this.getConfig().getAlias());
      uriBuilder.queryParam(KC_IDP_HINT, hint);
    }
    return uriBuilder;
  }
}
