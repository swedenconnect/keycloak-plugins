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

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.ClientSessionCode;
import se.swedenconnect.keycloak.oidc.ResourceMapper;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Authenticator that validates the RFC 8707 {@code resource} parameter at the authorization
 * endpoint, stores the result in the authentication-session note {@code auth_resource_validated},
 * and then immediately redirects to the realm's Identity Provider.
 *
 * <p>By handling the IDP redirect itself, this authenticator can be placed as a REQUIRED
 * execution at the top level of the browser flow without conflicting with ALTERNATIVE elements
 * such as the Identity Provider Redirector.
 *
 * <p>When a {@code resource} parameter is present the authenticator resolves the set of
 * permitted resources from the client's {@code resource-mapper} protocol-mapper configuration.
 * If no mapper is configured, or the mapper carries no resource list, the request is rejected
 * with {@code invalid_target}. The same error is returned when any of the requested resource
 * URIs is not in the permitted set.
 *
 * <p>After successful validation (or when no {@code resource} parameter is present) the
 * authenticator selects the IDP to redirect to by first checking the {@code kc_idp_hint}
 * client note and falling back to the first enabled IDP in the realm.
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
    validateAndRedirect(context);
  }

  @Override
  public void action(final AuthenticationFlowContext context) {
    // IDP callback is processed by the broker endpoint; nothing to do here.
    context.attempted();
  }

  /**
   * Validates the {@code resource} parameter from the authorization request and then
   * redirects to the configured Identity Provider.
   *
   * @param context the authentication-flow context
   */
  private static void validateAndRedirect(final AuthenticationFlowContext context) {
    final String clientRequestParamResource = context.getAuthenticationSession()
        .getClientNotes().get("client_request_param_resource");

    if (clientRequestParamResource == null || clientRequestParamResource.isBlank()) {
      log.debugf("RFC 8707 ResourceAuthenticator: no resource parameter in request");
      context.getAuthenticationSession().setClientNote(VALIDATED_RESOURCE_ATT, "");
      redirectToIdp(context);
      return;
    }

    final List<String> requestedResources = Arrays.stream(clientRequestParamResource.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();

    final Optional<String> resourcesConfig = getModel(context)
        .flatMap(model -> Optional.ofNullable(model.getConfig().get("attribute.resource.resources")));

    if (resourcesConfig.isEmpty()) {
      log.warnf("RFC 8707 ResourceAuthenticator: no resource-mapper configured for client [%s]",
          context.getAuthenticationSession().getClient().getClientId());
      throw new AuthenticationFlowException(
          AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
          "Client requested a resource indicator but no resource-mapper is configured",
          INVALID_TARGET);
    }

    final Set<String> allowedResources = Arrays.stream(resourcesConfig.get().split(","))
        .map(String::trim)
        .collect(Collectors.toSet());

    if (!allowedResources.containsAll(requestedResources)) {
      log.warnf("RFC 8707 ResourceAuthenticator: requested resources %s not all in allowed set %s",
          requestedResources, allowedResources);
      throw new AuthenticationFlowException(
          AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
          "Client resource request prohibited by policy",
          INVALID_TARGET);
    }

    context.getAuthenticationSession().setClientNote(VALIDATED_RESOURCE_ATT, String.join(",", requestedResources));
    log.debugf("RFC 8707 ResourceAuthenticator: resource indicator validated [%s]", requestedResources);
    redirectToIdp(context);
  }

  /**
   * Redirects the user to the Identity Provider, replicating the behaviour of
   * {@code IdentityProviderAuthenticator}. The IDP is selected by checking the
   * {@code kc_idp_hint} client note first, then falling back to the first enabled IDP.
   *
   * @param context the authentication-flow context
   */
  private static void redirectToIdp(final AuthenticationFlowContext context) {
    final String idpHint = context.getAuthenticationSession().getClientNote("kc_idp_hint");

    final IdentityProviderModel idpModel;
    if (idpHint != null && !idpHint.isBlank()) {
      idpModel = context.getRealm().getIdentityProviderByAlias(idpHint);
      if (idpModel == null) {
        throw new AuthenticationFlowException(
            "Identity provider not found for kc_idp_hint: " + idpHint,
            AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
      }
    } else {
      idpModel = context.getRealm().getIdentityProvidersStream()
          .filter(IdentityProviderModel::isEnabled)
          .findFirst()
          .orElseThrow(() -> new AuthenticationFlowException(
              "No enabled identity provider found in realm",
              AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR));
    }

    final String accessCode = new ClientSessionCode<>(
        context.getSession(), context.getRealm(), context.getAuthenticationSession()
    ).getOrGenerateCode();

    final String clientId = context.getAuthenticationSession().getClient().getClientId();
    final String tabId = context.getAuthenticationSession().getTabId();
    final String clientData = AuthenticationProcessor.getClientData(
        context.getSession(), context.getAuthenticationSession());

    final URI location = Urls.identityProviderAuthnRequest(
        context.getUriInfo().getBaseUri(),
        idpModel.getAlias(),
        context.getRealm().getName(),
        accessCode, clientId, tabId, clientData, null);

    log.debugf("RFC 8707 ResourceAuthenticator: redirecting to IDP [%s]", idpModel.getAlias());
    context.forceChallenge(Response.seeOther(location).build());
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
    return true;
  }

  @Override
  public void setRequiredActions(final KeycloakSession session, final RealmModel realm, final UserModel user) {
  }

  @Override
  public void close() {
  }
}
