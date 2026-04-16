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
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.TokenRefreshContext;
import org.keycloak.services.clientpolicy.context.TokenRequestContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Client policy executor that validates the RFC 8707 {@code resource} indicator parameter
 * at the token endpoint for both the authorization-code exchange and the refresh-token grant.
 *
 * <p>On {@code TOKEN_REQUEST} the executor checks that the requested resources are a subset of
 * what was established during the authorization request (stored in the client-session note
 * {@code auth_resource_validated} by {@link se.swedenconnect.keycloak.authenticator.ResourceAuthenticator}).
 * A narrower set is accepted and stored as a session attribute so that {@link ResourceMapper}
 * can apply it when building the access token.
 *
 * <p>On {@code TOKEN_REFRESH} the executor validates the {@code resource} parameter against
 * the set of resources configured on the client's {@code resource-mapper} protocol mapper.
 * The validated value is again stored as a session attribute for the mapper to consume.
 *
 * <p>If validation fails a {@link ClientPolicyException} with error code {@code invalid_target}
 * is thrown, which Keycloak translates to a well-formed RFC 6749 / RFC 8707 error response.
 *
 * @author Felix Hellman
 */
public class Rfc8707TokenEndpointExecutor
    implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

  private static final Logger log = Logger.getLogger(Rfc8707TokenEndpointExecutor.class);

  /**
   * {@link KeycloakSession} attribute key under which the validated resource string is stored
   * so that {@link ResourceMapper} can read it during token generation in the same request.
   */
  static final String SESSION_ATTR_VALIDATED_RESOURCE = "rfc8707.validated_resource";

  /** Client-session note written by {@link se.swedenconnect.keycloak.authenticator.ResourceAuthenticator}. */
  private static final String AUTH_RESOURCE_VALIDATED = "auth_resource_validated";

  /** RFC 8707 §7 error code returned when a resource indicator is not permitted. */
  static final String INVALID_TARGET = "invalid_target";

  /** Protocol-mapper ID for the resource mapper. */
  private static final String RESOURCE_MAPPER_ID = "resource-mapper";

  /** Config key for the CSV list of allowed resources on the resource mapper. */
  private static final String CONFIG_KEY_RESOURCES = "attribute.resource.resources";

  private final KeycloakSession session;

  /**
   * Creates a new executor bound to the given session.
   *
   * @param session the current Keycloak session
   */
  public Rfc8707TokenEndpointExecutor(final KeycloakSession session) {
    this.session = session;
  }

  @Override
  public void executeOnEvent(final ClientPolicyContext context) throws ClientPolicyException {
    switch (context.getEvent()) {
      case TOKEN_REQUEST -> this.executeOnTokenRequest((TokenRequestContext) context);
      case TOKEN_REFRESH -> this.executeOnTokenRefresh((TokenRefreshContext) context);
      default -> { /* other events not relevant to RFC 8707 */ }
    }
  }

  /**
   * Handles the authorization-code exchange token request.
   *
   * <p>If a {@code resource} parameter is present its values must be a subset of the resources
   * authorized during the authorization request. The intersection is stored as a session attribute.
   *
   * @param context the token-request policy context
   * @throws ClientPolicyException with {@code invalid_target} if the resource is not permitted
   */
  private void executeOnTokenRequest(final TokenRequestContext context) throws ClientPolicyException {
    final List<String> rawResourceParams = context.getParams().get("resource");
    if (rawResourceParams == null || rawResourceParams.isEmpty()) {
      // No resource at token endpoint — propagate the auth-time resource into the session
      // attribute so ResourceMapper can set aud without relying on the note-transfer path.
      if (context.getParseResult() != null && context.getParseResult().getClientSession() != null) {
        final String authResource = context.getParseResult().getClientSession().getNote(AUTH_RESOURCE_VALIDATED);
        if (authResource != null && !authResource.isBlank()) {
          this.session.setAttribute(SESSION_ATTR_VALIDATED_RESOURCE, authResource);
        }
      }
      return;
    }
    // Rfc8707RequestWrapper collapses multiple resource= values to one comma-joined string
    // to bypass Keycloak's duplicate-parameter check; expand back here.
    final List<String> resourceParams = rawResourceParams.stream()
        .flatMap(v -> Arrays.stream(v.split(",")))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .collect(Collectors.toList());

    if (context.getParseResult() == null || context.getParseResult().getClientSession() == null) {
      log.warnf("TOKEN_REQUEST: no client session available; skipping RFC 8707 resource validation");
      return;
    }

    final String authNote = context.getParseResult().getClientSession().getNote(AUTH_RESOURCE_VALIDATED);
    if (authNote == null || authNote.isBlank()) {
      throw new ClientPolicyException(
          INVALID_TARGET,
          "Resource indicator not established during the authorization request",
          Response.Status.BAD_REQUEST);
    }

    final Set<String> authorizedResources = Arrays.stream(authNote.split(","))
        .map(String::trim)
        .collect(Collectors.toSet());

    if (!authorizedResources.containsAll(resourceParams)) {
      throw new ClientPolicyException(
          INVALID_TARGET,
          "Requested resource was not authorized during the authorization request",
          Response.Status.BAD_REQUEST);
    }

    this.session.setAttribute(SESSION_ATTR_VALIDATED_RESOURCE, String.join(",", resourceParams));
    log.debugf("TOKEN_REQUEST: resource indicator narrowed to [%s]", resourceParams);
  }

  /**
   * Handles the refresh-token grant.
   *
   * <p>If a {@code resource} parameter is present its values are validated against the set
   * of resources configured on the client's {@code resource-mapper} protocol mapper.
   * The validated value is stored as a session attribute for {@link ResourceMapper} to consume.
   *
   * @param context the token-refresh policy context
   * @throws ClientPolicyException with {@code invalid_target} if the resource is not permitted
   */
  private void executeOnTokenRefresh(final TokenRefreshContext context) throws ClientPolicyException {
    final List<String> rawResourceParams = context.getParams().get("resource");
    if (rawResourceParams == null || rawResourceParams.isEmpty()) {
      return;
    }
    // Rfc8707RequestWrapper collapses multiple resource= values to one comma-joined string;
    // expand back here.
    final List<String> resourceParams = rawResourceParams.stream()
        .flatMap(v -> Arrays.stream(v.split(",")))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .collect(Collectors.toList());

    final Set<String> allowedResources = getAllowedResourcesForClient(context.getClient());
    if (allowedResources.isEmpty()) {
      throw new ClientPolicyException(
          INVALID_TARGET,
          "No resource indicators are configured for this client",
          Response.Status.BAD_REQUEST);
    }

    if (!allowedResources.containsAll(resourceParams)) {
      throw new ClientPolicyException(
          INVALID_TARGET,
          "Requested resource is not permitted for this client",
          Response.Status.BAD_REQUEST);
    }

    this.session.setAttribute(SESSION_ATTR_VALIDATED_RESOURCE, String.join(",", resourceParams));
    log.debugf("TOKEN_REFRESH: validated resource indicator [%s]", resourceParams);
  }

  /**
   * Returns the set of resource URIs permitted for the given client by inspecting its
   * {@code resource-mapper} protocol-mapper configuration.
   *
   * @param client the client model
   * @return set of allowed resource URIs, empty if none configured
   */
  private static Set<String> getAllowedResourcesForClient(final ClientModel client) {
    return client.getProtocolMappersStream()
        .filter(mapper -> RESOURCE_MAPPER_ID.equals(mapper.getProtocolMapper()))
        .findFirst()
        .map(ProtocolMapperModel::getConfig)
        .map(config -> config.get(CONFIG_KEY_RESOURCES))
        .map(csv -> Arrays.stream(csv.split(",")).map(String::trim).collect(Collectors.toSet()))
        .orElse(Set.of());
  }

  @Override
  public String getProviderId() {
    return Rfc8707TokenEndpointExecutorFactory.PROVIDER_ID;
  }
}
