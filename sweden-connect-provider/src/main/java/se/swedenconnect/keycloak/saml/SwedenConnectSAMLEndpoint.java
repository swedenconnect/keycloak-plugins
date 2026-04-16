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
package se.swedenconnect.keycloak.saml;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

/**
 * SAML endpoint that forwards cancel responses back to the OAuth2 client's redirect_uri
 * instead of showing Keycloak's error page.
 *
 * @author Felix Hellman
 */
public class SwedenConnectSAMLEndpoint extends SAMLEndpoint {

  private static final URI CANCEL_STATUS_URI = URI.create("http://id.elegnamnden.se/status/1.0/cancel");

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

  private final KeycloakSession keycloakSession;

  /**
   * Constructor.
   *
   * @param session session
   * @param provider provider
   * @param config config
   * @param callback callback
   * @param destinationValidator destinationValidator
   */
  public SwedenConnectSAMLEndpoint(
      final KeycloakSession session,
      final SAMLIdentityProvider provider,
      final SAMLIdentityProviderConfig config,
      final IdentityProvider.AuthenticationCallback callback,
      final DestinationValidator destinationValidator) {
    super(session, provider, config, callback, destinationValidator);
    this.keycloakSession = session;
  }

  @GET
  @Override
  public Response redirectBinding(
      @QueryParam(GeneralConstants.SAML_REQUEST_KEY) final String samlRequest,
      @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) final String samlResponse,
      @QueryParam(GeneralConstants.SAML_ARTIFACT_KEY) final String samlArt,
      @QueryParam(GeneralConstants.RELAY_STATE) final String relayState) {
    if (Objects.isNull(samlArt)) {
      return new SwedenConnectRedirectBinding().execute(samlRequest, samlResponse, null, relayState, null);
    }
    return super.redirectBinding(samlRequest, samlResponse, samlArt, relayState);
  }

  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Override
  public Response postBinding(
      @FormParam(GeneralConstants.SAML_REQUEST_KEY) final String samlRequest,
      @FormParam(GeneralConstants.SAML_RESPONSE_KEY) final String samlResponse,
      @FormParam(GeneralConstants.SAML_ARTIFACT_KEY) final String samlArt,
      @FormParam(GeneralConstants.RELAY_STATE) final String relayState) {
    if (Objects.isNull(samlArt)) {
      return new SwedenConnectPostBinding().execute(samlRequest, samlResponse, null, relayState, null);
    }
    return super.postBinding(samlRequest, samlResponse, samlArt, relayState);
  }

  protected Response handleCancelResponse(final String relayState) {
    final AuthenticationSessionModel authSession = callback.getAndVerifyAuthenticationSession(relayState);
    this.keycloakSession.getContext().setAuthenticationSession(authSession);

    final String encodedDescription = URLEncoder.encode(
        "Authentication cancelled by user.", StandardCharsets.UTF_8);

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
  }

  private boolean isCancelStatus(final org.keycloak.dom.saml.v2.protocol.ResponseType responseType) {
    return responseType.getStatus() != null
        && responseType.getStatus().getStatusCode() != null
        && responseType.getStatus().getStatusCode().getStatusCode() != null
        && CANCEL_STATUS_URI.equals(responseType.getStatus().getStatusCode().getStatusCode().getValue());
  }

  protected class SwedenConnectPostBinding extends PostBinding {
    @Override
    protected Response handleLoginResponse(
        final String samlResponse,
        final SAMLDocumentHolder holder,
        final org.keycloak.dom.saml.v2.protocol.ResponseType responseType,
        final String relayState,
        final String clientId) {

      if (SwedenConnectSAMLEndpoint.this.isCancelStatus(responseType) && StringUtil.isNotBlank(relayState)) {
        try {
          return SwedenConnectSAMLEndpoint.this.handleCancelResponse(relayState);
        } catch (final Exception e) {
          logger.warn("Failed to handle cancel response, falling back to default error handling", e);
        }
      }
      return super.handleLoginResponse(samlResponse, holder, responseType, relayState, clientId);
    }
  }

  protected class SwedenConnectRedirectBinding extends RedirectBinding {
    @Override
    protected Response handleLoginResponse(
        final String samlResponse,
        final SAMLDocumentHolder holder,
        final org.keycloak.dom.saml.v2.protocol.ResponseType responseType,
        final String relayState,
        final String clientId) {

      if (SwedenConnectSAMLEndpoint.this.isCancelStatus(responseType) && StringUtil.isNotBlank(relayState)) {
        try {
          return SwedenConnectSAMLEndpoint.this.handleCancelResponse(relayState);
        } catch (final Exception e) {
          logger.warn("Failed to handle cancel response, falling back to default error handling", e);
        }
      }
      return super.handleLoginResponse(samlResponse, holder, responseType, relayState, clientId);
    }
  }
}
