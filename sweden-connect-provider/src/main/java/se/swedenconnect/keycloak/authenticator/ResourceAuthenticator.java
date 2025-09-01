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
 * Authenticator class for validating resource parameter in auth request.
 *
 * @author Felix Hellman
 */
public class ResourceAuthenticator implements Authenticator {
  private static final Logger log = Logger.getLogger(ResourceMapper.class);

  @Override
  public void authenticate(final AuthenticationFlowContext context) {
    validate(context);
  }

  private static Optional<ProtocolMapperModel> getModel(final AuthenticationFlowContext context) {
    return context.getAuthenticationSession()
        .getClient().getProtocolMappersStream()
        .filter(mapper -> mapper.getProtocolMapper().equals("resource-mapper"))
        .findFirst();
  }

  @Override
  public void action(final AuthenticationFlowContext context) {
    validate(context);
  }

  private static void validate(final AuthenticationFlowContext context) {
    final List<String> resource = Arrays.stream(
        context.getAuthenticationSession().getClientNotes().get("client_request_param_resource").split(",")
    ).toList();

    if(resource.isEmpty()){
      log.debugf("No resource parameter found in request");
      return;
    }
    getModel(context)
        .flatMap(model -> Optional.ofNullable(model.getConfig()
            .get("attribute.resource.resources"))
        ).ifPresent(csv -> {
          final Set<String> allowedResources = Arrays.stream(
              csv.split(",")).collect(Collectors.toSet()
          );

          if (!allowedResources.containsAll(resource)) {
            throw new AuthenticationFlowException(
                AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
                "Client resource request prohibited",
                "invalid_target"
                );
          }
          context.getAuthenticationSession()
                  .setClientNote("auth_resource_validated", String.join(",", resource));
          context.success();
        });
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
