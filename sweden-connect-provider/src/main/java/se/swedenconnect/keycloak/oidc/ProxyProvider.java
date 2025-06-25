/*
 * Copyright 2025 Sweden Connect
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
 *
 */
package se.swedenconnect.keycloak.oidc;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.models.KeycloakSession;

import java.util.ArrayList;
import java.util.List;

/**
 * Docs
 *
 * @author Felix Hellman
 */
public class ProxyProvider extends KeycloakOIDCIdentityProvider {

  private static final List<String> PROXIED_SCOPES = List.of(
      "https://id.oidc.se/scope/naturalPersonNumber",
      "https://id.oidc.se/scope/naturalPersonInfo",
      "https://id.oidc.se/scope/naturalPersonOrgId",
      "https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity",
      "https://id.swedenconnect.se/scope/eidasSwedishIdentity"
  );

  /**
   * Constructor.
   *
   * @param session
   * @param config
   */
  public ProxyProvider(
      final KeycloakSession session,
      final OIDCIdentityProviderConfig config) {
    super(session, config);
  }

  @Override
  public Response performLogin(final AuthenticationRequest request) {
    return super.performLogin(request);
  }

  @Override
  protected UriBuilder createAuthorizationUrl(final AuthenticationRequest request) {
    final List<String> requestedScopes = new ArrayList<>();
    requestedScopes.add("openid");
    final String scope = request.getAuthenticationSession().getClientNotes().get("scope");
    PROXIED_SCOPES.forEach(proxy -> {
      if (scope.contains(proxy)) {
        requestedScopes.add(proxy);
      }
    });
    final UriBuilder authorizationUrl = super.createAuthorizationUrl(request);
    if (requestedScopes.size() > 1) {
      return authorizationUrl.replaceQueryParam("scope", String.join(" ", requestedScopes));
    }
    return authorizationUrl;
  }
}
