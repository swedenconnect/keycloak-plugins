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
import org.jboss.logging.Logger;
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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
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
public class OIDCMapper extends AbstractOIDCProtocolMapper
    implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

  private static final String ATTRIBUTE_ACCESS_TOKEN_KEY = "attribute.access.token.key";
  private static final String ATTRIBUTE_ID_TOKEN_KEY = "attribute.id.token.key";
  private static final String ATTRIBUTE_USERINFO_TOKEN_KEY = "attribute.userinfo.token.key";

  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final Logger log = Logger.getLogger(OIDCMapper.class);

  @Override
  public AccessToken transformAccessToken(
      final AccessToken accessToken,
      final ProtocolMapperModel mapperModel,
      final KeycloakSession keycloakSession,
      final UserSessionModel userSessionModel,
      final ClientSessionContext context) {

    accessToken.getOtherClaims().put("acr", null);
    accessToken.setAuthorization(null);
    accessToken.setOtherClaims("client_id", context.getClientSession().getClient().getClientId());
    log.infof("CONFIG %s", mapperModel.getConfig());

    this.mapClaims(
        accessToken,
        userSessionModel,
        a -> false,
        this.getTokenConfiguration(mapperModel, ATTRIBUTE_ACCESS_TOKEN_KEY)
    );

    return accessToken;
  }

  @Override
  public IDToken transformIDToken(
      final IDToken idToken,
      final ProtocolMapperModel mapperModel,
      final KeycloakSession keycloakSession,
      final UserSessionModel userSessionModel,
      final ClientSessionContext context) {

    final ClaimsParameter claimsParameter = this.getClaimsParameterFromContext(
        context, ClaimsParameter.TokenType.ID
    );

    idToken.setAuth_time((long) context.getClientSession().getStarted());

    final String acr = userSessionModel.getNote("acr");
    if (acr != null) {
      idToken.setAcr(acr);
    }

    this.mapClaims(idToken, userSessionModel, claimsParameter, this.getTokenConfiguration(mapperModel, ATTRIBUTE_ID_TOKEN_KEY));
    logRequiredClaims(claimsParameter, idToken, "idtoken", context);

    return idToken;
  }

  private static void logRequiredClaims(
      final ClaimsParameter claimsParameter,
      final IDToken idToken,
      final String tokeType,
      final ClientSessionContext clientSessionContext) {

    final HashSet<String> requiredParams = new HashSet<>(claimsParameter.getRequiredParameters());
    requiredParams.removeAll(idToken.getOtherClaims().keySet());

    // Special handling for pnr and coordination number, do not log if only one is present
    final List<String> naturalPersonNumber = List.of(
        "https://id.oidc.se/claim/coordinationNumber",
        "https://id.oidc.se/claim/personalIdentityNumber"
    );
    if (!requiredParams.containsAll(naturalPersonNumber)) {
      // At least one claim was not present, so we can remove them as they exclude each other.
      requiredParams.removeAll(naturalPersonNumber);
    }

    if (!requiredParams.isEmpty()) {
      log.infof("Required claims %s could not be mapped for %s@client:%s", requiredParams,
          tokeType,
          clientSessionContext.getClientSession().getClient().getClientId());
    }
  }

  @Override
  public AccessToken transformUserInfoToken(
      final AccessToken accessToken,
      final ProtocolMapperModel mapperModel,
      final KeycloakSession keycloakSession,
      final UserSessionModel userSessionModel,
      final ClientSessionContext clientSessionContext) {

    final ClaimsParameter claimsParameter =
        this.getClaimsParameterFromContext(clientSessionContext, ClaimsParameter.TokenType.USERINFO);

    this.mapClaims(accessToken, userSessionModel, claimsParameter, this.getTokenConfiguration(mapperModel, ATTRIBUTE_USERINFO_TOKEN_KEY));

    logRequiredClaims(claimsParameter, accessToken, "userinfo", clientSessionContext);

    return accessToken;
  }

  private void mapClaims(
      final IDToken accessToken,
      final UserSessionModel userSessionModel,
      final Predicate<AttributeClaim> shouldMap,
      final Map<String, String> config) {

    final String json = userSessionModel.getNote("SAML_ATTRIBUTES_JSON");

    try {
      final Map<String, Object> claims = MAPPER.readerFor(Map.class).readValue(json);
      AttributeToClaim.ATTRIBUTE_MAPPINGS.forEach(mapper -> {
        if (shouldMap.negate().test(mapper)) {
          return;
        }
        this.mapClaim(accessToken, mapper, claims);
      });
      //Do not check if claims from config should map or not
      AttributeToClaim.fromConfiguration(config).forEach(mapper -> {
        this.mapClaim(accessToken, mapper, claims);
      });
    } catch (final JsonProcessingException e) {
      throw new IllegalArgumentException("Could not process arguments from SAML attributes", e);
    }
  }

  private ClaimsParameter getClaimsParameterFromContext(
      final ClientSessionContext context,
      final ClaimsParameter.TokenType tokenType) {

    final ClaimsParameter claims = Optional.ofNullable(context.getClientSession().getNotes().get("claims")).map(c -> {
      try {
        return (Map<String, Object>) MAPPER.readerFor(Map.class).readValue(c);
      } catch (final JsonProcessingException e) {
        throw new RuntimeException(e);
      }
    }).map(cp -> new ClaimsParameter(cp, tokenType)).orElse(new ClaimsParameter(Map.of(), tokenType));

    Arrays.stream(context.getScopeString(true).split(" "))
        .forEach(scope -> {
          if (Objects.nonNull(scope)) {
            final ClaimsParameter other = ClaimsParameter.fromScope(scope);
            if (Objects.nonNull(other)) {
              claims.merge(other);
            }
          }
        });

    return claims;
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

    final ProviderConfigProperty accessToken = new ProviderConfigProperty();
    accessToken.setType(ProviderConfigProperty.MAP_TYPE);
    accessToken.setLabel("Access Token Mappings");
    accessToken.setHelpText("SAML Attribute to OIDC Claim Mapping");
    accessToken.setName(ATTRIBUTE_ACCESS_TOKEN_KEY);
    providerConfigProperties.add(accessToken);

    final ProviderConfigProperty idToken = new ProviderConfigProperty();
    idToken.setType(ProviderConfigProperty.MAP_TYPE);
    idToken.setLabel("Id Token Mappings");
    idToken.setHelpText("SAML Attribute to OIDC Claim Mapping");
    idToken.setName(ATTRIBUTE_ID_TOKEN_KEY);
    providerConfigProperties.add(idToken);

    final ProviderConfigProperty userInfoToken = new ProviderConfigProperty();
    userInfoToken.setType(ProviderConfigProperty.MAP_TYPE);
    userInfoToken.setLabel("UserInfo Token Mappings");
    userInfoToken.setHelpText("SAML Attribute to OIDC Claim Mapping");
    userInfoToken.setName(ATTRIBUTE_USERINFO_TOKEN_KEY);
    providerConfigProperties.add(userInfoToken);

    return providerConfigProperties;
  }

  private Map<String, String> getTokenConfiguration(final ProtocolMapperModel mapperModel, final String key) {
    final String json = mapperModel.getConfig().get(key);
    if (Objects.isNull(json) || json.isBlank()) {
      return Map.of();
    }
    try {
      final Map<String, String> configMap = new HashMap<>();
      final List<Map<String, String>> value = MAPPER.readerFor(List.class).readValue(json);
      value.forEach(v -> configMap.put(v.get("key"), v.get("value")));
      return configMap;
    } catch (final Exception e) {
      log.errorf("Failed to load json configuration from token mapping %s", e.getMessage());
      return Map.of();
    }
  }

  @Override
  public String getId() {
    return "Sweden-Connect";
  }
}
