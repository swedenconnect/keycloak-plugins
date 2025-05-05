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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;


/**
 * Mapper that implments mapping according to
 * <a href="https://www.oidc.se/specifications/claim-mappings-to-other-specs.html">oidc.se</a>
 *
 * @author Felix Hellman
 */
public class OIDCMapper
    extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Override
  public AccessToken transformAccessToken(
      final AccessToken accessToken,
      final ProtocolMapperModel protocolMapperModel,
      final KeycloakSession keycloakSession,
      final UserSessionModel userSessionModel,
      final ClientSessionContext context) {

    final String acr = userSessionModel.getNote("acr");
    if (acr != null) {
      accessToken.getOtherClaims().put("acr", acr);
    }

    final String username = userSessionModel.getUser().getUsername();
    accessToken.getOtherClaims().put("sub", username);

    this.mapClaims(
        accessToken,
        userSessionModel,
        protocolMapperModel,
        AttributeClaim::getAccessToken
    );

    return accessToken;
  }

  @Override
  public IDToken transformIDToken(
      final IDToken idToken,
      final ProtocolMapperModel protocolMapperModel,
      final KeycloakSession keycloakSession,
      final UserSessionModel userSessionModel,
      final ClientSessionContext clientSessionContext) {

    this.mapClaims(
        idToken,
        userSessionModel,
        protocolMapperModel,
        AttributeClaim::getIdToken
    );
    return idToken;
  }

  @Override
  public AccessToken transformUserInfoToken(
      final AccessToken accessToken,
      final ProtocolMapperModel protocolMapperModel,
      final KeycloakSession keycloakSession,
      final UserSessionModel userSessionModel,
      final ClientSessionContext clientSessionContext) {

    this.mapClaims(
        accessToken,
        userSessionModel,
        protocolMapperModel,
        AttributeClaim::getUserInfo
    );
    return accessToken;
  }

  private void mapClaims(
      final IDToken accessToken,
      final UserSessionModel userSessionModel,
      final ProtocolMapperModel protocolMapperModel,
      final Predicate<AttributeClaim> shouldMap) {

    final String json = userSessionModel.getNote("SAML_ATTRIBUTES_JSON");

    try {
      final Map<String, Object> claims = MAPPER.readerFor(Map.class).readValue(json);
      AttributeToClaim.ATTRIBUTE_MAPPINGS.forEach(mapper -> {
        if (shouldMap.negate().test(mapper)) {
          return;
        }
        this.mapClaim(accessToken, mapper, claims);
      });
      AttributeToClaim.NON_DEFAULT_CLAIMS.values().forEach(ac -> {
        final Optional<String> config = Optional.ofNullable(protocolMapperModel.getConfig().get(ac.getOidcClaimName()));
        if (config.isPresent() && Boolean.parseBoolean(config.get())) {
          this.mapClaim(accessToken, ac, claims);
        }
      });
    } catch (final JsonProcessingException e) {
      throw new IllegalArgumentException("Could not process arguments from SAML attributes", e);
    }
  }

  private void mapClaim(final IDToken accessToken, final AttributeClaim mapper, final Map<String, Object> claims) {
    final Object value = claims.get(mapper.getSamlAttributeName());
    if (Objects.isNull(value)) {
      return;
    }
    if (value instanceof List<?> list) {
      if (list.size() == 1) {
        accessToken.getOtherClaims().put(mapper.getOidcClaimName(), list.getFirst());
      } else {
        accessToken.getOtherClaims().put(mapper.getOidcClaimName(), value);
      }
    } else {
      accessToken.getOtherClaims().put(mapper.getOidcClaimName(), value);
    }
  }

  @Override
  public String getDisplayCategory() {
    return "Sweden Connect";
  }

  @Override
  public String getDisplayType() {
    return "Sweden Connect";
  }

  @Override
  public String getHelpText() {
    return "Sweden Connect";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    final List<ProviderConfigProperty> providerConfigProperties = new ArrayList<>();

    AttributeToClaim.NON_DEFAULT_CLAIMS.values().forEach(ac -> {
      final ProviderConfigProperty property = new ProviderConfigProperty();
      property.setName(ac.getOidcClaimName());
      property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
      property.setDefaultValue(false);
      property.setLabel("""
          claim: %s
          """.formatted(ac.getOidcClaimName()));
      property.setHelpText("Enable mapping of %s to token".formatted(ac.getOidcClaimName()));
      providerConfigProperties.add(property);
    });

    return providerConfigProperties;
  }

  @Override
  public String getId() {
    return "Sweden-Connect";
  }
}
