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
package se.swedenconnect.keycloak.oidf;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import se.swedenconnect.oidf.common.entity.entity.SigningEntityConfigurationFactory;
import se.swedenconnect.oidf.common.entity.entity.integration.registry.records.EntityRecord;
import se.swedenconnect.oidf.common.entity.entity.integration.registry.records.HostedRecord;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Realm resource provider for OIDF endpoints.
 *
 * @author Felix Hellman
 */
public class OIDFResourceProvider implements RealmResourceProvider {

  private final KeycloakSession session;

  /**
   * Constructor.
   *
   * @param session
   */
  public OIDFResourceProvider(final KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Override
  public void close() {

  }

  /**
   * @return entity configuration
   */
  @GET
  @Path(".well-known/openid-federation")
  public Response oidfResponse() {
    final RealmModel realm = this.session.getContext().getRealm();

    if (!realm.getAttribute("openid-federation", false)) {
      return Response.status(404).build();
    }

    final String realmName = realm.getName();

    final String issuer = this.session.getContext().getUri().getBaseUriBuilder()
        .path("/realms/{realm}")
        .buildFromMap(Map.of("realm", realmName))
        .toString();

    final String tokenEndpoint = this.session.getContext().getUri().getBaseUriBuilder()
        .path("/realms/{realm}/protocol/openid-connect/token")
        .buildFromMap(Map.of("realm", realmName))
        .toString();

    final String authEndpoint = this.session.getContext().getUri().getBaseUriBuilder()
        .path("/realms/{realm}/protocol/openid-connect/auth")
        .buildFromMap(Map.of("realm", realmName))
        .toString();

    final String userInfoEndpoint = this.session.getContext().getUri().getBaseUriBuilder()
        .path("/realms/{realm}/protocol/openid-connect/userinfo")
        .buildFromMap(Map.of("realm", realmName))
        .toString();

    final KeycloakSignerFactory keycloakSignerFactory = new KeycloakSignerFactory(this.session);
    final KeycloakFederationClient federationClient = new KeycloakFederationClient(this.session);

    final SigningEntityConfigurationFactory signingFactory = new SigningEntityConfigurationFactory(
        keycloakSignerFactory,
        federationClient,
        List.of()
    );

    final Map<String, Object> metadata = createMetadata(issuer,
        authEndpoint,
        tokenEndpoint,
        userInfoEndpoint,
        keycloakSignerFactory
    );
    final JWKSet signKey = new JWKSet(keycloakSignerFactory.getSignKey());
    final EntityRecord entityRecord = new EntityRecord(
        new EntityID(issuer),
        new EntityID(issuer), null,
        signKey.toPublicJWKSet(), null,
        new HostedRecord(metadata, List.of(), List.of()),
        List.of(), List.of());


    final EntityStatement entityConfiguration = signingFactory.createEntityConfiguration(entityRecord);
    final String response = entityConfiguration.getSignedStatement().serialize();
    return Response.ok(response).build();
  }

  private static Map<String, Object> createMetadata(
      final String issuer,
      final String authorizationEndpoint,
      final String tokenEndpoint,
      final String userInfoEndpoint,
      final KeycloakSignerFactory signingFactory
  ) {
    final Map<String, Object> map = Map.of(
        "issuer", issuer,
        "authorization_endpoint", authorizationEndpoint,
        "userinfo_endpoint", userInfoEndpoint,
        "token_endpoint", tokenEndpoint,
        "client_registration_types_supported", List.of("explicit"),
        "grant_types_supported", List.of(
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        ),
        "id_token_signing_alg_values_supported", List.of("RS256"),
        "response_types_supported", List.of("code", "token"),
        "subject_types_supported", List.of("pairwise"),
        "token_endpoint_auth_methos_supported", List.of("private_key_jwt"));

    final HashMap<String, Object> metadata = new HashMap<>(map);
    metadata.put("token_endpoint_auth_signing_alg_values_supported", "RS256");
    metadata.put("jwks", signingFactory.getMetadataKeys().toJSONObject());

    return Map.of("openid_provider", metadata);
  }
}
