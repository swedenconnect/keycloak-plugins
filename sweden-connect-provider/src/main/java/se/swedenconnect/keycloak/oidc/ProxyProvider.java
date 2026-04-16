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

import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

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

  private static final String REDIRECT_HTML = """
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="0;url=%s">
        <title>Redirecting...</title>
      </head>
      <body>
        <p>You are being redirected to <a href="%s">example.com</a>.
        If you are not redirected automatically, click the link.</p>
      </body>
      </html>
      """;

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
  public Object callback(final RealmModel realm, final IdentityProvider.AuthenticationCallback callback,
      final EventBuilder event) {
    return new ProxyEndpoint(callback, realm, event, this);
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

  protected static class ProxyEndpoint extends KeycloakOIDCIdentityProvider.KeycloakEndpoint {

    public ProxyEndpoint(final IdentityProvider.AuthenticationCallback callback, final RealmModel realm,
        final EventBuilder event, final KeycloakOIDCIdentityProvider provider) {
      super(callback, realm, event, provider);
    }

    @GET
    @Override
    public Response authResponse(
        @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) final String state,
        @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) final String authorizationCode,
        @QueryParam(OAuth2Constants.ERROR) final String error,
        @QueryParam(OAuth2Constants.ERROR_DESCRIPTION) final String errorDescription) {

      if (error == null || !error.equals(AbstractOAuth2IdentityProvider.ACCESS_DENIED) || state == null) {
        return super.authResponse(state, authorizationCode, error, errorDescription);
      }

      try {
        final AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);
        session.getContext().setAuthenticationSession(authSession);

        final String encodedDescription = URLEncoder.encode(
            Optional.ofNullable(errorDescription).orElse("Authentication cancelled by user."),
            StandardCharsets.UTF_8);

        final StringBuilder redirect = new StringBuilder(authSession.getRedirectUri())
            .append("?error=access_denied")
            .append("&error_description=").append(encodedDescription);

        Optional.ofNullable(authSession.getClientNote("state"))
            .ifPresent(s -> redirect.append("&state=").append(s));

        Optional.ofNullable(authSession.getClientNote("iss"))
            .ifPresent(i -> redirect.append("&iss=").append(i));

        final String url = redirect.toString();
        return Response.ok(REDIRECT_HTML.formatted(url, url))
            .type(MediaType.TEXT_HTML_TYPE)
            .build();

      } catch (final Exception e) {
        return super.authResponse(state, authorizationCode, error, errorDescription);
      }
    }
  }
}
