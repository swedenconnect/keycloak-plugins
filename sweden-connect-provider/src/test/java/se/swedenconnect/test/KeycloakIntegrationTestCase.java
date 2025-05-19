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

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.jetbrains.annotations.NotNull;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import se.swedenconnect.keycloak.ClientConfiguration;
import se.swedenconnect.keycloak.TestAuthServer;
import se.swedenconnect.keycloak.TestClient;
import se.swedenconnect.keycloak.TestClientJsonResponse;
import se.swedenconnect.keycloak.oidc.ResourceMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;

public class KeycloakIntegrationTestCase {
  public static final String TESTCLIENT = "https://testclient.se";
  private final Consumer<AuthenticationRequest.Builder> requestCustomizer;
  private final KeycloakContainer keycloakContainer;
  private final UUID realmName = UUID.randomUUID();

  public KeycloakIntegrationTestCase(final Consumer<AuthenticationRequest.Builder> requestCustomizer,
                                     final KeycloakContainer keycloakContainer) {

    this.requestCustomizer = requestCustomizer;
    this.keycloakContainer = keycloakContainer;
  }

  public TestClientJsonResponse execute() throws Exception {
    final Keycloak admin = keycloakContainer.getKeycloakAdminClient();
    final TestAuthServer authServer = new TestAuthServer();

    KeycloakConfigurer.configureRealm(admin, this.realmName.toString());
    KeycloakConfigurer.configureClient(admin, this.realmName.toString());
    KeycloakConfigurer.configureUserRegistration(admin, this.realmName.toString());
    KeycloakConfigurer.configureIdentityProvider(admin, authServer, this.realmName.toString());

    final TestClient testClient = configureTestClient(
        admin,
        keycloakContainer
    );

    authServer.start();

    testClient.startAuth(requestCustomizer);
    Thread.sleep(1_000_000L);

    while (Objects.isNull(testClient.getResponse())) {
      //Wait for test to complete
      Thread.sleep(500L);
    }
    return testClient.getResponse();
  }

  private @NotNull TestClient configureTestClient(final Keycloak admin, final KeycloakContainer keycloakContainer) throws IOException {
    final RealmResource test = admin.realm(this.realmName.toString());
    final String clientSecret = test.clients().findByClientId(TESTCLIENT)
        .getFirst()
        .getSecret();
    return new TestClient(new ClientConfiguration(Map.of(
        "client-id", TESTCLIENT,
        "client-secret", clientSecret,
        "auth-endpoint",
        keycloakContainer.getAuthServerUrl() + "/realms/%s/protocol/openid-connect/auth".formatted(this.realmName.toString()),
        "token-endpoint", keycloakContainer.getAuthServerUrl() + "/realms/%s/protocol/openid-connect/token".formatted(this.realmName.toString()),
        "userinfo-endpoint", keycloakContainer.getAuthServerUrl() + "/realms/%s/protocol/openid-connect/userinfo".formatted(this.realmName.toString())
    )), false);
  }
}
