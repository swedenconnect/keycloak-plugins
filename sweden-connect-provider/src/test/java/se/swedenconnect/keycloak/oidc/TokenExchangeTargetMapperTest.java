/*
 * Copyright 2026 Sweden Connect
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

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.protocol.oidc.mappers.AudienceProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenExchangeTargetMapperTest {

  private static final String RS1 = "https://localhost:18091";
  private static final String RS2 = "https://localhost:18092";
  private static final String RS3 = "https://localhost:18093";

  @Test
  void valuesAreSplitOnCommasWithoutDuplicates() {
    final Set<String> values = new LinkedHashSet<>();
    TokenExchangeTargetMapper.splitValues(values, List.of(RS1 + ", " + RS2, RS1, " "));
    TokenExchangeTargetMapper.splitValues(values, null);
    assertEquals(List.of(RS1, RS2), List.copyOf(values));
  }

  @Test
  void aTargetAddsItsScopeAndAudienceAndOtherResourceScopesAreRemoved() {
    final AccessToken token = new AccessToken();
    token.setScope("openid rs3 profile");
    token.addAudience(RS3);

    TokenExchangeTargetMapper.addTargets(token, List.of(
        source("rs1", RS1), source("rs2", RS2), source("rs3", RS3)), Set.of(RS1), true);

    assertEquals("openid profile rs1", token.getScope());
    assertTrue(token.hasAudience(RS1));
  }

  @Test
  void otherResourceScopesCanBeKept() {
    final AccessToken token = new AccessToken();
    token.setScope("openid rs3");
    TokenExchangeTargetMapper.addTargets(token, List.of(source("rs1", RS1), source("rs3", RS3)), Set.of(RS1), false);
    assertEquals("openid rs3 rs1", token.getScope());
  }

  @Test
  void theClientsOwnAudienceMapperAddsAudienceButNoScope() {
    final AccessToken token = new AccessToken();
    token.setScope("openid");
    TokenExchangeTargetMapper.addTargets(token,
        List.of(new TokenExchangeTargetMapper.AudienceSource(null, Set.of(RS2))), Set.of(RS2), true);
    assertEquals("openid", token.getScope());
    assertTrue(token.hasAudience(RS2));
  }

  @Test
  void aTargetThatNoScopeGivesIsNotAdded() {
    final AccessToken token = new AccessToken();
    token.setScope("openid");
    TokenExchangeTargetMapper.addTargets(token, List.of(source("rs1", RS1)), Set.of(RS2), true);
    assertNull(token.getAudience());
    assertEquals("openid", token.getScope());
  }

  @Test
  void permissionScopesMustBeInTheSubjectToken() {
    final AccessToken token = new AccessToken();
    token.setScope("openid resource:read resource:write");
    TokenExchangeTargetMapper.removeUnauthorizedPermissionScopes(token,
        Set.of("resource:read", "resource:write"), List.of("openid", "resource:read"));
    assertEquals("openid resource:read", token.getScope());

    final AccessToken unknown = new AccessToken();
    unknown.setScope("resource:write");
    TokenExchangeTargetMapper.removeUnauthorizedPermissionScopes(unknown, Set.of("resource:write"), null);
    assertEquals("resource:write", unknown.getScope());
  }

  @Test
  void subjectTokenScopes() {
    assertEquals(List.of("openid", "resource:read"),
        TokenExchangeTargetMapper.subjectTokenScopes(jwt("{\"scope\":\"openid resource:read\"}")));
    assertEquals(List.of(), TokenExchangeTargetMapper.subjectTokenScopes(jwt("{\"sub\":\"x\"}")));
    assertNull(TokenExchangeTargetMapper.subjectTokenScopes("opaque"));
    assertNull(TokenExchangeTargetMapper.subjectTokenScopes(null));
  }

  @Test
  void mapperAudiences() {
    assertEquals(List.of(RS1), TokenExchangeTargetMapper.mapperAudiences(audienceMapper(RS1, true)));
    assertEquals(List.of(), TokenExchangeTargetMapper.mapperAudiences(audienceMapper(RS1, false)));
    final ProtocolMapperModel other = new ProtocolMapperModel();
    other.setProtocolMapper("oidc-usermodel-attribute-mapper");
    other.setConfig(Map.of(AudienceProtocolMapper.INCLUDED_CUSTOM_AUDIENCE, RS1));
    assertEquals(List.of(), TokenExchangeTargetMapper.mapperAudiences(other));
  }

  @Test
  void audienceSourcesAndPermissionScopesOfAClient() {
    final ClientScopeModel rs1 = scope("rs1", audienceMapper(RS1, true));
    final ClientScopeModel read = scope("resource:read");
    final ClientScopeModel profile = scope("profile", new ProtocolMapperModel());
    final ClientModel client = mock(ClientModel.class);
    when(client.getProtocolMappersStream()).thenAnswer(i -> Stream.of(audienceMapper(RS2, true)));
    when(client.getClientScopes(true)).thenReturn(Map.of("profile", profile));
    when(client.getClientScopes(false)).thenReturn(Map.of("rs1", rs1, "resource:read", read));

    final List<TokenExchangeTargetMapper.AudienceSource> sources = TokenExchangeTargetMapper.audienceSources(client);
    assertEquals(2, sources.size());
    assertNull(sources.get(0).scope());
    assertEquals(Set.of(RS2), sources.get(0).audiences());
    assertEquals(rs1, sources.get(1).scope());

    assertEquals(Set.of("resource:read"), TokenExchangeTargetMapper.permissionScopes(client));
  }

  @Test
  void theResponseIsNarrowedToTheRequestedResourcesAndSignedAgain() {
    final TestSession test = new TestSession(form(RS1));
    final TokenExchangeTargetMapper mapper = new TokenExchangeTargetMapper();
    final AccessToken token = new AccessToken();
    token.setScope("openid rs3");
    token.addAudience(RS3);
    final IDToken idToken = new IDToken();

    mapper.transformAccessToken(token, config(), test.session, null, null);
    mapper.transformIDToken(idToken, config(), test.session, null, null);
    assertEquals("openid rs1", token.getScope());
    assertTrue(token.hasAudience(RS1) && token.hasAudience(RS3));

    final AccessTokenResponse response = response();
    mapper.transformAccessTokenResponse(response, config(), test.session, null, null);
    assertArrayEquals(new String[] { RS1 }, token.getAudience());
    assertEquals("re-encoded", response.getToken());
    assertEquals("re-encoded-id", response.getIdToken());
    assertNull(test.attributes.get(TokenExchangeTargetMapper.STATE));
  }

  @Test
  void aResourceThatNoScopeGivesMeansInvalidTarget() {
    final TestSession test = new TestSession(form("https://unknown.example"));
    final TokenExchangeTargetMapper mapper = new TokenExchangeTargetMapper();
    mapper.transformAccessToken(new AccessToken(), config(), test.session, null, null);

    final AccessTokenResponse response = response();
    mapper.transformAccessTokenResponse(response, config(), test.session, null, null);
    assertNull(response.getToken());
    assertNull(response.getIdToken());
    assertEquals(TokenExchangeTargetMapper.INVALID_TARGET, response.getError());
    assertEquals("Requested resource not available: https://unknown.example", response.getErrorDescription());
  }

  @Test
  void otherGrantsAreNotTouched() {
    final MultivaluedMap<String, String> form = form(RS1);
    form.putSingle(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE);
    final TestSession test = new TestSession(form);
    final AccessToken token = new AccessToken();
    token.setScope("openid rs3");
    new TokenExchangeTargetMapper().transformAccessToken(token, config(), test.session, null, null);
    assertEquals("openid rs3", token.getScope());
    assertTrue(test.attributes.isEmpty());
  }

  /** A mocked session for a token exchange request by a client with scopes rs1 and rs3. */
  private static final class TestSession {
    private final Map<String, Object> attributes = new HashMap<>();
    private final KeycloakSession session = mock(KeycloakSession.class, Mockito.RETURNS_DEEP_STUBS);

    private TestSession(final MultivaluedMap<String, String> form) {
      final ClientScopeModel rs1 = scope("rs1", audienceMapper(RS1, true));
      final ClientScopeModel rs3 = scope("rs3", audienceMapper(RS3, true));
      final ClientModel client = mock(ClientModel.class);
      when(client.getClientId()).thenReturn("client1");
      when(client.getProtocolMappersStream()).thenAnswer(i -> Stream.empty());
      when(client.getClientScopes(true)).thenReturn(Map.of("rs3", rs3));
      when(client.getClientScopes(false)).thenReturn(Map.of("rs1", rs1));

      when(this.session.getContext().getClient()).thenReturn(client);
      when(this.session.getContext().getUri().getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
      when(this.session.getContext().getHttpRequest().getDecodedFormParameters()).thenReturn(form);
      when(this.session.getAttribute(anyString())).thenAnswer(i -> this.attributes.get(i.<String>getArgument(0)));
      Mockito.doAnswer(i -> this.attributes.put(i.getArgument(0), i.getArgument(1)))
          .when(this.session).setAttribute(anyString(), any());
      Mockito.doAnswer(i -> this.attributes.remove(i.<String>getArgument(0)))
          .when(this.session).removeAttribute(anyString());
      when(this.session.tokens().encode(any())).thenReturn("re-encoded");
      when(this.session.tokens().encodeAndEncrypt(any())).thenReturn("re-encoded-id");
    }
  }

  private static MultivaluedMap<String, String> form(final String resource) {
    final MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.putSingle(OAuth2Constants.GRANT_TYPE, OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE);
    form.putSingle(OAuth2Constants.RESOURCE, resource);
    return form;
  }

  private static AccessTokenResponse response() {
    final AccessTokenResponse response = new AccessTokenResponse();
    response.setToken("original");
    response.setIdToken("original-id");
    return response;
  }

  private static ProtocolMapperModel config() {
    final ProtocolMapperModel mapper = new ProtocolMapperModel();
    mapper.setProtocolMapper(TokenExchangeTargetMapper.PROVIDER_ID);
    final Map<String, String> config = new LinkedHashMap<>();
    config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
    config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
    config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN_RESPONSE, "true");
    mapper.setConfig(config);
    return mapper;
  }

  private static TokenExchangeTargetMapper.AudienceSource source(final String scopeName, final String audience) {
    return new TokenExchangeTargetMapper.AudienceSource(scope(scopeName), Set.of(audience));
  }

  private static ClientScopeModel scope(final String name, final ProtocolMapperModel... mappers) {
    final ClientScopeModel scope = mock(ClientScopeModel.class);
    when(scope.getName()).thenReturn(name);
    when(scope.isIncludeInTokenScope()).thenReturn(true);
    when(scope.getProtocolMappersStream()).thenAnswer(i -> Stream.of(mappers));
    return scope;
  }

  private static ProtocolMapperModel audienceMapper(final String audience, final boolean inAccessToken) {
    final ProtocolMapperModel mapper = new ProtocolMapperModel();
    mapper.setProtocolMapper(AudienceProtocolMapper.PROVIDER_ID);
    mapper.setConfig(Map.of(AudienceProtocolMapper.INCLUDED_CUSTOM_AUDIENCE, audience,
        OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, String.valueOf(inAccessToken)));
    return mapper;
  }

  private static String jwt(final String payload) {
    final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    return encoder.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "."
        + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".sig";
  }
}
