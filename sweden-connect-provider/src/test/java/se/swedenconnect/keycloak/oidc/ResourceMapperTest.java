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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessToken;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

class ResourceMapperTest {

  private static final String API       = "https://api.example.com";
  private static final String OTHER_API = "https://other-api.example.com";

  private static final String SCOPE_MAPPING_TWO_RESOURCES =
      "[{\"key\":\"" + API + "\",\"value\":\"read write\"}," +
      "{\"key\":\"" + OTHER_API + "\",\"value\":\"read\"}]";

  private static final String SCOPE_MAPPING_SINGLE_RESOURCE =
      "[{\"key\":\"" + API + "\",\"value\":\"read write\"}]";

  private ResourceMapper mapper;
  private KeycloakSession session;
  private ClientSessionContext clientSessionContext;
  private AuthenticatedClientSessionModel clientSession;
  private ProtocolMapperModel mapperModel;

  @BeforeEach
  void setUp() {
    mapper = new ResourceMapper();
    session = Mockito.mock(KeycloakSession.class);
    clientSessionContext = Mockito.mock(ClientSessionContext.class);
    clientSession = Mockito.mock(AuthenticatedClientSessionModel.class);
    mapperModel = Mockito.mock(ProtocolMapperModel.class);

    when(clientSessionContext.getClientSession()).thenReturn(clientSession);
    when(session.getAttribute(Rfc8707TokenEndpointExecutor.SESSION_ATTR_VALIDATED_RESOURCE)).thenReturn(null);
    when(clientSession.getNote("auth_resource_validated")).thenReturn(null);
  }

  @Test
  void sessionAttributeTakesPriorityOverClientNote() {
    when(session.getAttribute(Rfc8707TokenEndpointExecutor.SESSION_ATTR_VALIDATED_RESOURCE))
        .thenReturn(API);
    when(clientSession.getNote("auth_resource_validated")).thenReturn(OTHER_API);
    when(mapperModel.getConfig()).thenReturn(Map.of("attribute.resource.scope.mapping", SCOPE_MAPPING_SINGLE_RESOURCE));

    final AccessToken token = tokenWithScope("openid read write");
    mapper.transformAccessToken(token, mapperModel, session, Mockito.mock(UserSessionModel.class), clientSessionContext);

    final Set<String> scopes = scopeSet(token);
    assertTrue(scopes.contains("read"));
    assertTrue(scopes.contains("write"));
  }

  @Test
  void noResourceSkipsDownscoping() {
    final AccessToken token = tokenWithScope("openid read write basic");
    mapper.transformAccessToken(token, mapperModel, session, Mockito.mock(UserSessionModel.class), clientSessionContext);

    assertEquals(Set.of("openid", "read", "write", "basic"), scopeSet(token));
  }

  @Test
  void singleResourceDownscopesCorrectly() {
    when(clientSession.getNote("auth_resource_validated")).thenReturn(OTHER_API);
    when(mapperModel.getConfig()).thenReturn(Map.of(
        "attribute.resource.scope.mapping",
        "[{\"key\":\"" + OTHER_API + "\",\"value\":\"read\"}]"
    ));

    final AccessToken token = tokenWithScope("openid read write basic");
    mapper.transformAccessToken(token, mapperModel, session, Mockito.mock(UserSessionModel.class), clientSessionContext);

    final Set<String> scopes = scopeSet(token);
    assertTrue(scopes.contains("openid"));
    assertTrue(scopes.contains("read"));
    assertTrue(!scopes.contains("write"));
    assertTrue(!scopes.contains("basic"));
  }

  @Test
  void twoResourcesIntersectionStripsWriteFromSecondResource() {
    when(clientSession.getNote("auth_resource_validated")).thenReturn(API + "," + OTHER_API);
    when(mapperModel.getConfig()).thenReturn(Map.of(
        "attribute.resource.scope.mapping", SCOPE_MAPPING_TWO_RESOURCES
    ));

    final AccessToken token = tokenWithScope("openid read write basic");
    mapper.transformAccessToken(token, mapperModel, session, Mockito.mock(UserSessionModel.class), clientSessionContext);

    final Set<String> scopes = scopeSet(token);
    assertTrue(scopes.contains("openid"));
    assertTrue(scopes.contains("read"));
    assertTrue(!scopes.contains("write"));
    assertTrue(!scopes.contains("basic"));
  }

  @Test
  void twoResourcesIntersectionViaSessionAttribute() {
    when(session.getAttribute(Rfc8707TokenEndpointExecutor.SESSION_ATTR_VALIDATED_RESOURCE))
        .thenReturn(API + "," + OTHER_API);
    when(mapperModel.getConfig()).thenReturn(Map.of(
        "attribute.resource.scope.mapping", SCOPE_MAPPING_TWO_RESOURCES
    ));

    final AccessToken token = tokenWithScope("openid read write");
    mapper.transformAccessToken(token, mapperModel, session, Mockito.mock(UserSessionModel.class), clientSessionContext);

    final Set<String> scopes = scopeSet(token);
    assertTrue(scopes.contains("read"));
    assertTrue(!scopes.contains("write"));
  }

  @Test
  void resourceWithNoScopeMappingDoesNotRestrict() {
    when(clientSession.getNote("auth_resource_validated")).thenReturn(API);
    when(mapperModel.getConfig()).thenReturn(Map.of("attribute.resource.scope.mapping", "[]"));

    final AccessToken token = tokenWithScope("openid read write basic");
    mapper.transformAccessToken(token, mapperModel, session, Mockito.mock(UserSessionModel.class), clientSessionContext);

    assertEquals(Set.of("openid", "read", "write", "basic"), scopeSet(token));
  }

  @Test
  void openidAlwaysSurvivesEvenIfNotInScopeMapping() {
    when(clientSession.getNote("auth_resource_validated")).thenReturn(API);
    when(mapperModel.getConfig()).thenReturn(Map.of(
        "attribute.resource.scope.mapping",
        "[{\"key\":\"" + API + "\",\"value\":\"read\"}]"
    ));

    final AccessToken token = tokenWithScope("openid read write");
    mapper.transformAccessToken(token, mapperModel, session, Mockito.mock(UserSessionModel.class), clientSessionContext);

    assertTrue(scopeSet(token).contains("openid"));
    assertTrue(!scopeSet(token).contains("write"));
  }

  @Test
  void singleResourceSetsSingleAud() {
    when(clientSession.getNote("auth_resource_validated")).thenReturn(API);
    when(mapperModel.getConfig()).thenReturn(Map.of(
        "attribute.resource.scope.mapping", SCOPE_MAPPING_SINGLE_RESOURCE
    ));

    final AccessToken token = tokenWithScope("openid read");
    mapper.transformAccessToken(token, mapperModel, session, Mockito.mock(UserSessionModel.class), clientSessionContext);

    assertEquals(API, token.getOtherClaims().get("aud"));
  }

  @Test
  void multipleResourcesSetsAudList() {
    when(clientSession.getNote("auth_resource_validated")).thenReturn(API + "," + OTHER_API);
    when(mapperModel.getConfig()).thenReturn(Map.of(
        "attribute.resource.scope.mapping", SCOPE_MAPPING_TWO_RESOURCES
    ));

    final AccessToken token = tokenWithScope("openid read");
    mapper.transformAccessToken(token, mapperModel, session, Mockito.mock(UserSessionModel.class), clientSessionContext);

    assertTrue(token.getOtherClaims().get("aud") instanceof java.util.List);
  }

  private static AccessToken tokenWithScope(final String scope) {
    final AccessToken token = new AccessToken();
    token.setScope(scope);
    return token;
  }

  private static Set<String> scopeSet(final AccessToken token) {
    return Arrays.stream(token.getScope().split(" "))
        .collect(Collectors.toSet());
  }
}
