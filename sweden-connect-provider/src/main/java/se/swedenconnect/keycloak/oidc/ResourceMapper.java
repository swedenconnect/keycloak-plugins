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

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Protocol mapper that translates a validated RFC 8707 resource indicator into {@code aud}
 * and down-scoped {@code scope} claims in the access token.
 *
 * <p>The mapper reads the resource to apply from two sources in priority order:
 * <ol>
 *   <li>The Keycloak session attribute {@code rfc8707.validated_resource} — written by
 *       {@link Rfc8707TokenEndpointExecutor} during the token-endpoint request when a
 *       {@code resource} parameter is present (auth-code exchange or refresh-token grant).
 *       When this attribute is present the mapper also persists it back into the client-session
 *       note {@code auth_resource_validated} so that subsequent refresh cycles without an
 *       explicit {@code resource} parameter continue to honour the narrowed audience.</li>
 *   <li>The client-session note {@code auth_resource_validated} — written by
 *       {@link se.swedenconnect.keycloak.authenticator.ResourceAuthenticator} during the
 *       authorization flow. This is the fallback for auth-code exchange and for refresh-token
 *       grants that do not supply a new {@code resource} parameter.</li>
 * </ol>
 *
 * <p>Relies on {@link se.swedenconnect.keycloak.authenticator.ResourceAuthenticator} being
 * present in the authentication flow to validate and store the resource during the
 * authorization request.
 *
 * @author Felix Hellman
 */
public class ResourceMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

  private static final Logger log = Logger.getLogger(ResourceMapper.class);

  private static final ObjectMapper MAPPER = new ObjectMapper();

  /** Client-session note that carries the resource validated at the authorization endpoint. */
  private static final String AUTH_RESOURCE_VALIDATED = "auth_resource_validated";

  @Override
  public AccessToken transformAccessToken(final AccessToken token,
      final ProtocolMapperModel mapper,
      final KeycloakSession session,
      final UserSessionModel userSession,
      final ClientSessionContext context) {

    final String validatedResource = this.resolveValidatedResource(session, context);

    if (validatedResource == null || validatedResource.isBlank()) {
      log.debugf("No validated resource parameter found; skipping resource-indicator token claims.");
      return token;
    }

    final List<String> aud = Arrays.stream(validatedResource.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();

    final List<String> filteredScopes = this.getDownScoped(token, mapper, aud);
    token.setScope(String.join(" ", filteredScopes));

    if (aud.size() == 1) {
      token.setOtherClaims("aud", aud.getFirst());
    } else {
      token.setOtherClaims("aud", aud);
    }

    return token;
  }

  /**
   * Returns the resource string to use for this token-generation cycle.
   *
   * <p>The session attribute written by {@link Rfc8707TokenEndpointExecutor} takes priority
   * over the client-session note from the authorization flow. When the attribute is used it is
   * also persisted back to the client-session note so that future refresh cycles without an
   * explicit {@code resource} parameter retain the narrowed audience.
   *
   * @param session Keycloak session for the current request
   * @param context the client-session context
   * @return comma-separated resource string, or {@code null} / blank if none
   */
  private String resolveValidatedResource(final KeycloakSession session, final ClientSessionContext context) {
    final String fromExecutor = (String) session.getAttribute(
        Rfc8707TokenEndpointExecutor.SESSION_ATTR_VALIDATED_RESOURCE);
    if (fromExecutor != null && !fromExecutor.isBlank()) {
      // Persist back so that the next refresh without an explicit resource parameter retains the audience.
      context.getClientSession().setNote(AUTH_RESOURCE_VALIDATED, fromExecutor);
      return fromExecutor;
    }
    return context.getClientSession().getNote(AUTH_RESOURCE_VALIDATED);
  }

  /**
   * Returns the subset of current token scopes that are permitted for the given audiences,
   * based on the audience-to-scope mapping configured on this mapper.
   *
   * @param token  the access token being built
   * @param mapper the protocol mapper model carrying the configuration
   * @param aud    the resolved audience list
   * @return list of scopes to include in the token
   */
  private List<String> getDownScoped(
      final AccessToken token, final ProtocolMapperModel mapper, final List<String> aud) {
    final List<String> scopes = Arrays.stream(token.getScope().split(" ")).toList();
    final Map<String, String> mapping = this.getConfiguration(mapper, "attribute.resource.scope.mapping");

    // Intersect allowed scopes across all audiences: a scope survives only if every
    // requested audience permits it. Using union (the previous approach) allowed write
    // to leak into tokens where one audience restricted it to read-only.
    final Set<String> allowed = new HashSet<>(scopes);
    for (final String audience : aud) {
      final String scopeConfig = mapping.get(audience);
      if (scopeConfig != null && !scopeConfig.isBlank()) {
        final Set<String> audienceAllowed = new HashSet<>(Arrays.asList(scopeConfig.split(" ")));
        audienceAllowed.add("openid");
        allowed.retainAll(audienceAllowed);
      }
    }
    allowed.add("openid"); // openid always survives

    return scopes.stream()
        .filter(allowed::contains)
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
    return "Maps a validated RFC 8707 resource indicator to aud and scope claims in the access token.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
        .property("attribute.resource.resources", "Resources",
            "CSV of resource URIs this client can request access for",
            ProviderConfigProperty.STRING_TYPE,
            "", List.of()
        )
        .property("attribute.resource.scope.mapping", "Scope Mappings",
            "Audience URI to space-separated scope mapping (used for down-scoping)",
            ProviderConfigProperty.MAP_TYPE,
            null, null
        )
        .build();
  }

  @Override
  public String getId() {
    return "resource-mapper";
  }

  /**
   * Parses a JSON map-type config value into a {@code Map<String, String>}.
   *
   * @param mapperModel the protocol mapper model
   * @param key         the config key to read
   * @return parsed map, or empty map on error or absence
   */
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
