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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.AccessToken;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Mapper class for implementing resource auth param to aud claim.
 * Relies on {@link se.swedenconnect.keycloak.authenticator.ResourceAuthenticator}
 * for validation of parameter.
 *
 * @author Felix Hellman.
 */
public class ResourceMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

  private static final Logger log = Logger.getLogger(ResourceMapper.class);

  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Override
  public AccessToken transformAccessToken(final AccessToken token,
                                          final ProtocolMapperModel mapper,
                                          final KeycloakSession session,
                                          final UserSessionModel userSession,
                                          final ClientSessionContext context) {
    final List<String> aud = Arrays.stream(context.getClientSession()
            .getNote("auth_resource_validated")
            .split(","))
        .toList();

    //Scope to filter down
    final List<String> filteredScopes = this.getDownScoped(token, mapper, aud);
    if (filteredScopes.size() > 1) {
      //If allowed scopes is only openid, we do no filtering
      token.setScope(String.join(" ", filteredScopes));
    }



    if (aud.size() == 1) {
      token.setOtherClaims("aud", aud.getFirst());
    } else {
      token.setOtherClaims("aud", aud);
    }

    return token;
  }

  private List<String> getDownScoped(
      final AccessToken token,
      final ProtocolMapperModel mapper,
      final List<String> aud) {

    final List<String> scopes = Arrays.stream(token.getScope().split(" ")).toList();
    final Map<String, String> mapping = this.getConfiguration(mapper, "attribute.resource.scope.mapping");
    final List<String> allowedScopes = new ArrayList<>();
    allowedScopes.add("openid");
    aud
        .forEach(a -> {
          Optional.ofNullable(mapping.get(a)).ifPresent(downscope -> {
            allowedScopes.addAll(Arrays.stream(downscope.split(" ")).toList());
          });
        });

    return scopes.stream()
        .filter(allowedScopes::contains)
        .distinct()
        .toList();
  }

  @Override
  public String getDisplayCategory() {
    return "resource-mapper";
  }

  @Override
  public String getDisplayType() {
    return "resource-mapper";
  }

  @Override
  public String getHelpText() {
    return "resource-mapper";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
        .property("attribute.resource.resources", "Resources",
            "CSV of resources this client can gain access for",
            ProviderConfigProperty.STRING_TYPE,
            "", List.of()
        )
        .property("attribute.resource.scope.mapping", "Scope Mappings",
            "audience to scope (space separated) mapping",
            ProviderConfigProperty.MAP_TYPE,
            null, null
        )
        .build();
  }

  @Override
  public String getId() {
    return "resource-mapper";
  }

  private Map<String, String> getConfiguration(final ProtocolMapperModel mapperModel, final String key) {
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
}
