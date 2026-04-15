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
package se.swedenconnect.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import se.swedenconnect.keycloak.oidc.ResourceMapper;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Authenticator that validates the RFC 8707 {@code resource} parameter at the authorization
 * endpoint and stores the result in the authentication-session note {@code auth_resource_validated}.
 *
 * <p>When no {@code resource} parameter is present in the request the authenticator succeeds
 * unconditionally and clears any previously stored validated-resource note.
 *
 * <p>When a {@code resource} parameter is present the authenticator resolves the set of
 * permitted resources from the client's {@code resource-mapper} protocol-mapper configuration.
 * If no mapper is configured, or the mapper carries no resource list, the request is rejected
 * with {@code invalid_target}. The same error is returned when any of the requested resource
 * URIs is not in the permitted set.
 *
 * @author Felix Hellman
 */
public class ResourceAuthenticator implements Authenticator {

  private static final Logger log = Logger.getLogger(ResourceMapper.class);

  /** Client-session note that carries the resource validated by this authenticator. */
  private static final String VALIDATED_RESOURCE_ATT = "auth_resource_validated";

  /** RFC 8707 §7 error code. */
  private static final String INVALID_TARGET = "invalid_target";

  @Override
  public void authenticate(final AuthenticationFlowContext context) {
    validate(context);
  }

  @Override
  public void action(final AuthenticationFlowContext context) {
    validate(context);
  }

  /**
   * Validates the {@code resource} parameter from the authorization request.
   *
   * @param context the authentication-flow context
   */
  private static void validate(final AuthenticationFlowContext context) {
    final String clientRequestParamResource = context.getAuthenticationSession()
        .getClientNotes().get("client_request_param_resource");

    if (clientRequestParamResource == null || clientRequestParamResource.isBlank()) {
      log.debugf("No resource parameter found in authorization request");
      context.getAuthenticationSession().setClientNote(VALIDATED_RESOURCE_ATT, "");
      context.success();
      return;
    }

    final List<String> requestedResources = Arrays.stream(clientRequestParamResource.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();

    final Optional<String> resourcesConfig = getModel(context)
        .flatMap(model -> Optional.ofNullable(model.getConfig().get("attribute.resource.resources")));

    if (resourcesConfig.isEmpty()) {
      throw new AuthenticationFlowException(
          AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
          "Client requested a resource indicator but no resource-mapper is configured",
          INVALID_TARGET);
    }

    final Set<String> allowedResources = Arrays.stream(resourcesConfig.get().split(","))
        .map(String::trim)
        .collect(Collectors.toSet());

    if (!allowedResources.containsAll(requestedResources)) {
      throw new AuthenticationFlowException(
          AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
          "Client resource request prohibited by policy",
          INVALID_TARGET);
    }

    context.getAuthenticationSession().setClientNote(VALIDATED_RESOURCE_ATT, String.join(",", requestedResources));
    context.success();
  }

  /**
   * Finds the first {@code resource-mapper} protocol mapper configured on the client.
   *
   * @param context the authentication-flow context
   * @return the mapper model, or empty if none is configured
   */
  private static Optional<ProtocolMapperModel> getModel(final AuthenticationFlowContext context) {
    return context.getAuthenticationSession()
        .getClient().getProtocolMappersStream()
        .filter(mapper -> mapper.getProtocolMapper().equals("resource-mapper"))
        .findFirst();
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean areRequiredActionsEnabled(final KeycloakSession session, final RealmModel realm) {
    return true;
  }

  @Override
  public boolean configuredFor(final KeycloakSession session, final RealmModel realm, final UserModel user) {
    return false;
  }

  @Override
  public void setRequiredActions(final KeycloakSession session, final RealmModel realm, final UserModel user) {
  }

  @Override
  public void close() {
  }
}
