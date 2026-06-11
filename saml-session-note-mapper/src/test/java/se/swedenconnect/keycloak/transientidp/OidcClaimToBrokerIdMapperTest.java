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
 */
package se.swedenconnect.keycloak.transientidp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OidcClaimToBrokerIdMapper}.
 *
 * @author David Goldring
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OidcClaimToBrokerIdMapperTest {

  @Mock
  private IdentityProviderMapperModel mapperModel;

  @Mock
  private BrokeredIdentityContext context;

  @Mock
  private IdentityProviderModel idpConfig;

  @Mock
  private KeycloakSession session;

  @Mock
  private RealmModel realm;

  @Mock
  private UserModel user;

  private OidcClaimToBrokerIdMapper mapper;
  private Map<String, Object> contextData;

  @BeforeEach
  void setUp() {
    this.mapper = new OidcClaimToBrokerIdMapper();
    this.contextData = new HashMap<>();
    when(this.context.getContextData()).thenReturn(this.contextData);
    when(this.context.getIdpConfig()).thenReturn(this.idpConfig);
    when(this.idpConfig.getAlias()).thenReturn("orgiam.realm");
  }

  @Test
  void claimPresent_setsId() {
    when(this.mapperModel.getConfig()).thenReturn(
        config(OidcClaimToBrokerIdMapper.CLAIM_NAME_CONFIG, "personalIdentityNumber"));
    this.contextData.put(OIDCIdentityProvider.VALIDATED_ID_TOKEN,
        tokenWithClaim("personalIdentityNumber", "191212121212"));

    this.mapper.preprocessFederatedIdentity(this.session, this.realm, this.mapperModel, this.context);

    verify(this.context).setId("191212121212");
    verify(this.context).setUsername("191212121212");
  }

  @Test
  void claimAbsent_doesNotSetIdOrUsername() {
    when(this.mapperModel.getConfig()).thenReturn(
        config(OidcClaimToBrokerIdMapper.CLAIM_NAME_CONFIG, "personalIdentityNumber"));
    this.contextData.put(OIDCIdentityProvider.VALIDATED_ID_TOKEN, new JsonWebToken());

    this.mapper.preprocessFederatedIdentity(this.session, this.realm, this.mapperModel, this.context);

    verify(this.context, never()).setId(any());
    verify(this.context, never()).setUsername(any());
  }

  @Test
  void claimBlank_doesNotSetIdOrUsername() {
    when(this.mapperModel.getConfig()).thenReturn(
        config(OidcClaimToBrokerIdMapper.CLAIM_NAME_CONFIG, "personalIdentityNumber"));
    this.contextData.put(OIDCIdentityProvider.VALIDATED_ID_TOKEN,
        tokenWithClaim("personalIdentityNumber", "  "));

    this.mapper.preprocessFederatedIdentity(this.session, this.realm, this.mapperModel, this.context);

    verify(this.context, never()).setId(any());
    verify(this.context, never()).setUsername(any());
  }

  @Test
  void noValidatedIdToken_doesNotSetIdOrUsername() {
    when(this.mapperModel.getConfig()).thenReturn(
        config(OidcClaimToBrokerIdMapper.CLAIM_NAME_CONFIG, "personalIdentityNumber"));
    // contextData left empty — no VALIDATED_ID_TOKEN entry

    this.mapper.preprocessFederatedIdentity(this.session, this.realm, this.mapperModel, this.context);

    verify(this.context, never()).setId(any());
    verify(this.context, never()).setUsername(any());
  }

  @Test
  void updateBrokeredUser_delegatesToPreprocessFederatedIdentity() {
    when(this.mapperModel.getConfig()).thenReturn(
        config(OidcClaimToBrokerIdMapper.CLAIM_NAME_CONFIG, "personalIdentityNumber"));
    this.contextData.put(OIDCIdentityProvider.VALIDATED_ID_TOKEN,
        tokenWithClaim("personalIdentityNumber", "197309069289"));

    this.mapper.updateBrokeredUser(this.session, this.realm, this.user, this.mapperModel, this.context);

    verify(this.context).setId("197309069289");
    verify(this.context).setUsername("197309069289");
  }

  @Test
  void customClaimName_readsFromCustomClaim() {
    when(this.mapperModel.getConfig()).thenReturn(
        config(OidcClaimToBrokerIdMapper.CLAIM_NAME_CONFIG, "pnr"));
    this.contextData.put(OIDCIdentityProvider.VALIDATED_ID_TOKEN,
        tokenWithClaim("pnr", "196408233234"));

    this.mapper.preprocessFederatedIdentity(this.session, this.realm, this.mapperModel, this.context);

    verify(this.context).setId("196408233234");
    verify(this.context).setUsername("196408233234");
  }

  @Test
  void resolveClaimName_configuredKey_returnsKey() {
    when(this.mapperModel.getConfig()).thenReturn(
        config(OidcClaimToBrokerIdMapper.CLAIM_NAME_CONFIG, "myCustomClaim"));

    assertEquals("myCustomClaim", OidcClaimToBrokerIdMapper.resolveClaimName(this.mapperModel));
  }

  @Test
  void resolveClaimName_nullKey_returnsDefault() {
    when(this.mapperModel.getConfig()).thenReturn(new HashMap<>());

    assertEquals(OidcClaimToBrokerIdMapper.DEFAULT_CLAIM_NAME,
        OidcClaimToBrokerIdMapper.resolveClaimName(this.mapperModel));
  }

  @Test
  void resolveClaimName_blankKey_returnsDefault() {
    when(this.mapperModel.getConfig()).thenReturn(
        config(OidcClaimToBrokerIdMapper.CLAIM_NAME_CONFIG, "  "));

    assertEquals(OidcClaimToBrokerIdMapper.DEFAULT_CLAIM_NAME,
        OidcClaimToBrokerIdMapper.resolveClaimName(this.mapperModel));
  }

  @Test
  void getId_returnsProviderId() {
    assertEquals(OidcClaimToBrokerIdMapper.PROVIDER_ID, this.mapper.getId());
  }

  // --- helpers ---

  private static JsonWebToken tokenWithClaim(final String claimName, final String value) {
    final JsonWebToken token = new JsonWebToken();
    token.getOtherClaims().put(claimName, value);
    return token;
  }

  private static Map<String, String> config(final String... keyValues) {
    final Map<String, String> map = new HashMap<>();
    for (int i = 0; i < keyValues.length - 1; i += 2) {
      map.put(keyValues[i], keyValues[i + 1]);
    }
    return map;
  }

}
