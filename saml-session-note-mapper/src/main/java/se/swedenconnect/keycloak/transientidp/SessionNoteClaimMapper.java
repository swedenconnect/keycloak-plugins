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

import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * An OIDC protocol mapper that reads a user session note and emits its value as a configurable
 * token claim.
 *
 * <p>This mapper is the downstream counterpart of {@link SamlSessionNoteMapper}. Configure it on
 * the OIDC client in the transient realm that issues tokens to the broker realm (e.g. orgiam).
 * It reads the note written by {@link SamlSessionNoteMapper} and emits it as a standard OIDC
 * claim so that the broker realm can use the value as a stable {@code identity_provider_identity}
 * via {@code principalType=ATTRIBUTE}.</p>
 *
 * <p>Default values for Sweden Connect personal identity numbers:</p>
 * <ul>
 *   <li>Session note key: {@value SamlSessionNoteMapper#DEFAULT_SESSION_NOTE}</li>
 *   <li>Claim name: {@value #DEFAULT_CLAIM_NAME} (dot-free to avoid Keycloak path-split issues)</li>
 * </ul>
 *
 * @author David Goldring
 */
public class SessionNoteClaimMapper extends AbstractOIDCProtocolMapper
    implements OIDCIDTokenMapper, OIDCAccessTokenMapper, UserInfoTokenMapper {

  private static final Logger LOG = Logger.getLogger(SessionNoteClaimMapper.class);

  /** Provider ID used to reference this mapper in Keycloak configuration. */
  public static final String PROVIDER_ID = "transient-session-note-claim-mapper";

  /** Configuration key for the user session note name to read. */
  public static final String SESSION_NOTE_CONFIG = "session.note";

  /**
   * Default OIDC claim name emitted by this mapper for the personal identity number.
   *
   * <p>A simple name without dots is used deliberately. Keycloak's {@code splitClaimPath}
   * splits claim names on unescaped dots when writing to the token, but the OIDC IdP's
   * {@code getJsonProperty} does a flat key lookup when reading {@code principalAttribute}.
   * Using a dot-free name avoids any mismatch between the two sides of the claim path.</p>
   *
   * <p>This claim is internal to the Transient→orgiam hop. The public-facing Sweden Connect
   * claim ({@code https://id.oidc.se/claim/personalIdentityNumber}) is emitted by a separate
   * mapper on the downstream orgiam client.</p>
   */
  public static final String DEFAULT_CLAIM_NAME = "personalIdentityNumber";

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    final List<ProviderConfigProperty> props = new ArrayList<>();

    final ProviderConfigProperty sessionNoteProp = new ProviderConfigProperty();
    sessionNoteProp.setName(SESSION_NOTE_CONFIG);
    sessionNoteProp.setLabel("User Session Note");
    sessionNoteProp.setHelpText(
        "Name of the note in UserSessionModel.getNote() to read. "
            + "Must match the note key configured on the \"SAML Attribute to Session Note\" "
            + "identity provider mapper on the upstream SAML identity provider(s).");
    sessionNoteProp.setType(ProviderConfigProperty.STRING_TYPE);
    sessionNoteProp.setDefaultValue(SamlSessionNoteMapper.DEFAULT_SESSION_NOTE);
    props.add(sessionNoteProp);

    OIDCAttributeMapperHelper.addAttributeConfig(props, SessionNoteClaimMapper.class);
    props.stream()
        .filter(p -> OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME.equals(p.getName()))
        .findFirst()
        .ifPresent(p -> p.setDefaultValue(DEFAULT_CLAIM_NAME));

    CONFIG_PROPERTIES = Collections.unmodifiableList(props);
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Session Note to Claim";
  }

  @Override
  public String getDisplayCategory() {
    return AbstractOIDCProtocolMapper.TOKEN_MAPPER_CATEGORY;
  }

  @Override
  public String getHelpText() {
    return "Reads a user session note and emits its value as a configurable OIDC token claim. "
        + "Pair with the \"SAML Attribute to Session Note\" identity provider mapper in a "
        + "transient (doNotStoreUsers=true) proxy realm to propagate SAML assertion attributes "
        + "into downstream OIDC tokens without persisting personal data in the transient realm. "
        + "Use a dot-free claim name (e.g. \"personalIdentityNumber\") and configure the same "
        + "name as the principalAttribute on the downstream broker identity provider. "
        + "Avoid URL-style claim names with dots — Keycloak's path splitting and the IdP's "
        + "flat claim lookup are inconsistent for dot-containing names.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  @Override
  protected void setClaim(
      final IDToken token,
      final ProtocolMapperModel mappingModel,
      final UserSessionModel userSession,
      final KeycloakSession keycloakSession,
      final ClientSessionContext clientSessionCtx) {

    final String noteKey = resolveNoteKey(mappingModel);
    String value = userSession.getNote(noteKey);

    if (value == null || value.isBlank()) {
      // Fallback: read from the user model attribute. For lightweight (doNotStoreUsers=true)
      // users in some Keycloak versions, auth-session user-session-notes are not reliably
      // transferred to the UserSessionModel note map. The LightweightUserAdapter's attributes
      //  are, however, serialized into the keycloak.userModel session note and remain accessible
      // via getUser().getFirstAttribute(). SamlSessionNoteMapper.importNewUser/updateBrokeredUser
      // sets the attribute under the same key to enable this fallback.
      value = userSession.getUser().getFirstAttribute(noteKey);
    }

    if (value == null || value.isBlank()) {
      LOG.debugf("Session note '%s' absent in user session and no matching user attribute — "
          + "claim not added to token", noteKey);
      return;
    }

    OIDCAttributeMapperHelper.mapClaim(token, mappingModel, value);
    LOG.debugf("Mapped session note/attribute '%s' to token claim", noteKey);
  }

  /**
   * Resolves the effective session note key from the mapper model config, falling back to
   * {@link SamlSessionNoteMapper#DEFAULT_SESSION_NOTE} when the config entry is absent or blank.
   *
   * @param mappingModel the mapper configuration model
   * @return the session note key to use
   */
  static String resolveNoteKey(final ProtocolMapperModel mappingModel) {
    final String key = mappingModel.getConfig().get(SESSION_NOTE_CONFIG);
    return (key != null && !key.isBlank()) ? key : SamlSessionNoteMapper.DEFAULT_SESSION_NOTE;
  }

}
