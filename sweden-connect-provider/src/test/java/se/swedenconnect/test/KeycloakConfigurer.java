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
package se.swedenconnect.test;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.userprofile.config.UPConfig;
import se.swedenconnect.keycloak.TestAuthServer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KeycloakConfigurer {

  public static void configureIdentityProvider(final Keycloak admin,
                                               final TestAuthServer server,
                                               final String realmName) {

    final IdentityProviderRepresentation provider = new IdentityProviderRepresentation();

    provider.setAlias("proxy");
    provider.setProviderId("oidc");
    provider.setEnabled(true);
    provider.setHideOnLogin(false);

    final String tokenEndpoint = "http://host.docker.internal:%d/token"
        .formatted(server.getPort());
    provider.setConfig(
        Map.of(
            "tokenUrl", tokenEndpoint,
            "userInfoUrl", "http://host.docker.internal:%d/userinfo".formatted(server.getPort()),
            "disableUserInfo", "true",
            "authorizationUrl", "http://localhost:%d/auth".formatted(server.getPort()),
            "jwksUrl", "http://host.docker.internal:%d/certs".formatted(server.getPort()),
            "clientSecret", "clientsecret",
            "defaultScope", "openid",
            "useJwksUrl", "true",
            "clientId", "clientId"
        )
    );

    admin.realm(realmName).identityProviders()
        .create(provider)
        .close();

    final AuthenticationManagementResource flows = admin.realm(realmName).flows();

    final List<AuthenticationExecutionInfoRepresentation> executions = admin.realm(realmName).flows()
        .getExecutions("browser");

    final AuthenticationExecutionInfoRepresentation repr = executions.stream()
        .filter(e -> e.getProviderId().equals("identity-provider-redirector"))
        .findFirst()
        .get();

    final AuthenticatorConfigRepresentation acr = new AuthenticatorConfigRepresentation();
    acr.setAlias("selector");
    acr.setConfig(Map.of("defaultProvider", "proxy"));
    flows.newExecutionConfig(repr.getId(), acr).close();
  }

  public static void configureClient(final Keycloak admin, final String realmName) {
    final RealmResource test = admin.realm(realmName);
    List.of(
        "https://id.oidc.se/scope/naturalPersonNumber",
        "https://id.oidc.se/scope/naturalPersonOrgId",
        "https://id.oidc.se/scope/naturalPersonInfo"
    ).forEach(scope -> {
      final ClientScopeRepresentation clientScopeRepresentation = new ClientScopeRepresentation();
      clientScopeRepresentation.setName(scope);
      clientScopeRepresentation.setProtocol("openid-connect");
      final String s = test.clientScopes().create(clientScopeRepresentation).readEntity(String.class);
      System.out.println(s);
    });

    final ClientScopeRepresentation e = new ClientScopeRepresentation();
    final ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
    mapper.setProtocolMapper("resource-mapper");
    mapper.setName("resource-mapper");
    mapper.setProtocol("openid-connect");
    mapper.setConfig(new HashMap<>(Map.of("attribute.resource.resources", "https://api.test")));
    e.setName("resource");
    e.setProtocolMappers(new ArrayList<>(List.of(mapper)));
    test.clientScopes().create(e).close();

    final ClientRepresentation clientRepresentation = new ClientRepresentation();
    clientRepresentation.setClientId("https://testclient.se");
    clientRepresentation.setClientAuthenticatorType("confidential");
    clientRepresentation.setRedirectUris(List.of("*"));
    clientRepresentation.setClientAuthenticatorType("client-secret");
    clientRepresentation.setDefaultClientScopes(List.of("resource"));
    clientRepresentation.setOptionalClientScopes(List.of());
    test.clients().create(clientRepresentation).close();
  }

  public static void configureRealm(final Keycloak admin, final String realmName) {
    final RealmRepresentation realmRepresentation = new RealmRepresentation();
    realmRepresentation.setRealm(realmName);
    realmRepresentation.setEnabled(true);
    admin.realms()
        .create(realmRepresentation);
  }

  public static void configureUserRegistration(final Keycloak admin, final String realmName) {
    final RealmResource test = admin.realm(realmName);
    final UPConfig configuration = test.users()
        .userProfile()
        .getConfiguration();
    configuration
        .getAttribute("email")
        .setRequired(null);
    test.users()
        .userProfile()
        .update(configuration);
  }
}
