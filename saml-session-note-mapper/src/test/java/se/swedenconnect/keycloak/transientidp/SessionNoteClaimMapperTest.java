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
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.IDToken;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SessionNoteClaimMapper}.
 *
 * @author David Goldring
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SessionNoteClaimMapperTest {

  @Mock
  private ProtocolMapperModel mappingModel;

  @Mock
  private UserSessionModel userSession;

  @Mock
  private UserModel user;

  @Mock
  private KeycloakSession keycloakSession;

  @Mock
  private ClientSessionContext clientSessionCtx;

  private SessionNoteClaimMapper mapper;

  @BeforeEach
  void setUp() {
    this.mapper = new SessionNoteClaimMapper();
    when(this.userSession.getUser()).thenReturn(this.user);
  }

  @Test
  void notePresent_claimAddedToToken() {
    when(this.mappingModel.getConfig()).thenReturn(config(
        SessionNoteClaimMapper.SESSION_NOTE_CONFIG, SamlSessionNoteMapper.DEFAULT_SESSION_NOTE,
        "claim.name", SessionNoteClaimMapper.DEFAULT_CLAIM_NAME,
        "jsonType.label", "String",
        "id.token.claim", "true",
        "access.token.claim", "false",
        "userinfo.token.claim", "false"));
    when(this.userSession.getNote(SamlSessionNoteMapper.DEFAULT_SESSION_NOTE)).thenReturn("191212121212");

    final IDToken token = new IDToken();
    this.mapper.setClaim(token, this.mappingModel, this.userSession, this.keycloakSession, this.clientSessionCtx);

    assertEquals("191212121212",
        token.getOtherClaims().get(SessionNoteClaimMapper.DEFAULT_CLAIM_NAME));
  }

  @Test
  void noteAbsent_claimNotAdded() {
    when(this.mappingModel.getConfig()).thenReturn(config(
        SessionNoteClaimMapper.SESSION_NOTE_CONFIG, SamlSessionNoteMapper.DEFAULT_SESSION_NOTE,
        "claim.name", SessionNoteClaimMapper.DEFAULT_CLAIM_NAME,
        "jsonType.label", "String",
        "id.token.claim", "true"));
    when(this.userSession.getNote(SamlSessionNoteMapper.DEFAULT_SESSION_NOTE)).thenReturn(null);

    final IDToken token = new IDToken();
    this.mapper.setClaim(token, this.mappingModel, this.userSession, this.keycloakSession, this.clientSessionCtx);

    assertFalse(token.getOtherClaims().containsKey(SessionNoteClaimMapper.DEFAULT_CLAIM_NAME));
  }

  @Test
  void noteBlank_claimNotAdded() {
    when(this.mappingModel.getConfig()).thenReturn(config(
        SessionNoteClaimMapper.SESSION_NOTE_CONFIG, SamlSessionNoteMapper.DEFAULT_SESSION_NOTE,
        "claim.name", SessionNoteClaimMapper.DEFAULT_CLAIM_NAME,
        "jsonType.label", "String",
        "id.token.claim", "true"));
    when(this.userSession.getNote(SamlSessionNoteMapper.DEFAULT_SESSION_NOTE)).thenReturn("  ");

    final IDToken token = new IDToken();
    this.mapper.setClaim(token, this.mappingModel, this.userSession, this.keycloakSession, this.clientSessionCtx);

    assertFalse(token.getOtherClaims().containsKey(SessionNoteClaimMapper.DEFAULT_CLAIM_NAME));
  }

  @Test
  void customNoteKey_readsFromCustomKey() {
    when(this.mappingModel.getConfig()).thenReturn(config(
        SessionNoteClaimMapper.SESSION_NOTE_CONFIG, "my_note",
        "claim.name", "pnr",
        "jsonType.label", "String",
        "id.token.claim", "true",
        "access.token.claim", "false",
        "userinfo.token.claim", "false"));
    when(this.userSession.getNote("my_note")).thenReturn("197309069289");

    final IDToken token = new IDToken();
    this.mapper.setClaim(token, this.mappingModel, this.userSession, this.keycloakSession, this.clientSessionCtx);

    assertEquals("197309069289", token.getOtherClaims().get("pnr"));
  }

  @Test
  void resolveNoteKey_configuredKey_returnsConfiguredKey() {
    when(this.mappingModel.getConfig()).thenReturn(config(
        SessionNoteClaimMapper.SESSION_NOTE_CONFIG, "configured_note"));

    assertEquals("configured_note", SessionNoteClaimMapper.resolveNoteKey(this.mappingModel));
  }

  @Test
  void resolveNoteKey_nullKey_returnsDefault() {
    when(this.mappingModel.getConfig()).thenReturn(new HashMap<>());

    assertEquals(SamlSessionNoteMapper.DEFAULT_SESSION_NOTE,
        SessionNoteClaimMapper.resolveNoteKey(this.mappingModel));
  }

  @Test
  void resolveNoteKey_blankKey_returnsDefault() {
    when(this.mappingModel.getConfig()).thenReturn(config(
        SessionNoteClaimMapper.SESSION_NOTE_CONFIG, "  "));

    assertEquals(SamlSessionNoteMapper.DEFAULT_SESSION_NOTE,
        SessionNoteClaimMapper.resolveNoteKey(this.mappingModel));
  }

  @Test
  void getId_returnsExpectedId() {
    assertEquals(SessionNoteClaimMapper.PROVIDER_ID, this.mapper.getId());
  }

  @Test
  void getConfigProperties_includesSessionNoteProperty() {
    final boolean hasSessionNote = this.mapper.getConfigProperties().stream()
        .anyMatch(p -> SessionNoteClaimMapper.SESSION_NOTE_CONFIG.equals(p.getName()));
    assertTrue(hasSessionNote);
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
