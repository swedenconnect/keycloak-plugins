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
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SamlSessionNoteMapper}.
 *
 * @author David Goldring
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SamlSessionNoteMapperTest {

  @Mock
  private KeycloakSession session;

  @Mock
  private RealmModel realm;

  @Mock
  private IdentityProviderMapperModel mapperModel;

  @Mock
  private BrokeredIdentityContext context;

  @Mock
  private AuthenticationSessionModel authSession;

  @Mock
  private IdentityProviderModel idpConfig;

  private SamlSessionNoteMapper mapper;

  @BeforeEach
  void setUp() {
    this.mapper = spy(new SamlSessionNoteMapper());
    when(this.context.getAuthenticationSession()).thenReturn(this.authSession);
    when(this.context.getIdpConfig()).thenReturn(this.idpConfig);
    when(this.idpConfig.getAlias()).thenReturn("BankID");
  }

  @Test
  void pinFound_storedAsDefaultSessionNote() {
    when(this.mapperModel.getConfig()).thenReturn(config(
        SamlSessionNoteMapper.SAML_ATTRIBUTE_NAME, "urn:oid:1.2.752.29.4.13"));
    doReturn("191212121212").when(this.mapper).readAttribute(this.context, this.mapperModel);

    this.mapper.preprocessFederatedIdentity(this.session, this.realm, this.mapperModel, this.context);

    verify(this.authSession).setUserSessionNote(SamlSessionNoteMapper.DEFAULT_SESSION_NOTE, "191212121212");
  }

  @Test
  void pinFound_storedAsCustomSessionNote() {
    when(this.mapperModel.getConfig()).thenReturn(config(
        SamlSessionNoteMapper.SAML_ATTRIBUTE_NAME, "urn:oid:1.2.752.29.4.13",
        SamlSessionNoteMapper.SESSION_NOTE_CONFIG, "my_custom_note"));
    doReturn("197309069289").when(this.mapper).readAttribute(this.context, this.mapperModel);

    this.mapper.preprocessFederatedIdentity(this.session, this.realm, this.mapperModel, this.context);

    verify(this.authSession).setUserSessionNote("my_custom_note", "197309069289");
  }

  @Test
  void attributeNotFound_noSessionNoteWritten() {
    when(this.mapperModel.getConfig()).thenReturn(config(
        SamlSessionNoteMapper.SAML_ATTRIBUTE_NAME, "urn:oid:1.2.752.29.4.13"));
    doReturn(null).when(this.mapper).readAttribute(this.context, this.mapperModel);

    this.mapper.preprocessFederatedIdentity(this.session, this.realm, this.mapperModel, this.context);

    verify(this.authSession, never()).setUserSessionNote(any(), any());
  }

  @Test
  void attributeBlank_noSessionNoteWritten() {
    when(this.mapperModel.getConfig()).thenReturn(config(
        SamlSessionNoteMapper.SAML_ATTRIBUTE_NAME, "urn:oid:1.2.752.29.4.13"));
    doReturn("  ").when(this.mapper).readAttribute(this.context, this.mapperModel);

    this.mapper.preprocessFederatedIdentity(this.session, this.realm, this.mapperModel, this.context);

    verify(this.authSession, never()).setUserSessionNote(any(), any());
  }

  @Test
  void resolveNoteKey_configuredKey_returnsConfiguredKey() {
    when(this.mapperModel.getConfig()).thenReturn(config(
        SamlSessionNoteMapper.SESSION_NOTE_CONFIG, "custom_key"));

    assertEquals("custom_key", SamlSessionNoteMapper.resolveNoteKey(this.mapperModel));
  }

  @Test
  void resolveNoteKey_nullKey_returnsDefault() {
    when(this.mapperModel.getConfig()).thenReturn(new HashMap<>());

    assertEquals(SamlSessionNoteMapper.DEFAULT_SESSION_NOTE,
        SamlSessionNoteMapper.resolveNoteKey(this.mapperModel));
  }

  @Test
  void resolveNoteKey_blankKey_returnsDefault() {
    when(this.mapperModel.getConfig()).thenReturn(config(
        SamlSessionNoteMapper.SESSION_NOTE_CONFIG, "   "));

    assertEquals(SamlSessionNoteMapper.DEFAULT_SESSION_NOTE,
        SamlSessionNoteMapper.resolveNoteKey(this.mapperModel));
  }

  @Test
  void getId_returnsExpectedId() {
    assertEquals(SamlSessionNoteMapper.PROVIDER_ID, this.mapper.getId());
  }

  @Test
  void getConfigProperties_includesSessionNoteProperty() {
    final boolean hasSessionNote = this.mapper.getConfigProperties().stream()
        .anyMatch(p -> SamlSessionNoteMapper.SESSION_NOTE_CONFIG.equals(p.getName()));
    assertTrue(hasSessionNote);
  }

  @Test
  void getConfigProperties_includesSamlAttributeNameProperty() {
    final boolean hasAttributeName = this.mapper.getConfigProperties().stream()
        .anyMatch(p -> SamlSessionNoteMapper.SAML_ATTRIBUTE_NAME.equals(p.getName()));
    assertTrue(hasAttributeName);
  }

  // --- helpers ---

  private static Map<String, String> config(final String... keyValues) {
    final Map<String, String> map = new HashMap<>();
    for (int i = 0; i < keyValues.length - 1; i += 2) {
      map.put(keyValues[i], keyValues[i + 1]);
    }
    return map;
  }

}
