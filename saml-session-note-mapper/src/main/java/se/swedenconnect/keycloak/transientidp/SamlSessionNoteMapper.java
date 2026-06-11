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
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A SAML identity provider mapper that reads a configurable SAML assertion attribute and stores
 * its value as a user session note on the authentication session.
 *
 * <p>The note is transferred to the {@code UserSessionModel} after successful authentication and
 * is then available to OIDC protocol mappers — such as {@link SessionNoteClaimMapper} or the
 * built-in <em>User Session Note</em> mapper — during token generation.</p>
 *
 * <p>This mapper is designed for transient proxy realms where {@code doNotStoreUsers=true}
 * prevents user-model attributes from surviving beyond the current request. Because user session
 * notes live in the session rather than on the user model, the attribute value is correctly
 * propagated through the authorization code exchange even for lightweight (in-memory) users.</p>
 *
 * <p>Typical setup for Sweden Connect identity numbers:</p>
 * <ul>
 *   <li>Add one mapper instance per SAML IdP (BankID, RefIDP, eIDAS …) in the transient realm
 *       with {@code attribute.name = urn:oid:1.2.752.29.4.13} and
 *       {@code session.note = transient_personal_identity_number}.</li>
 *   <li>Optionally add a second instance for coordination numbers
 *       ({@code attribute.name = urn:oid:1.2.752.201.3.4}) writing to the same note key; the
 *       second instance is a no-op when the assertion only contains a personnummer.</li>
 *   <li>On the downstream OIDC client in the transient realm, add {@link SessionNoteClaimMapper}
 *       (or the built-in <em>User Session Note</em> mapper) to emit the note as a token claim.</li>
 * </ul>
 *
 * @author David Goldring
 */
public class SamlSessionNoteMapper extends AbstractIdentityProviderMapper {

  private static final Logger LOG = Logger.getLogger(SamlSessionNoteMapper.class);

  /** Provider ID used to reference this mapper in Keycloak configuration. */
  public static final String PROVIDER_ID = "saml-session-note-mapper";

  /** Configuration key for the SAML attribute name to read from the assertion. */
  public static final String SAML_ATTRIBUTE_NAME = "attribute.name";

  /** Configuration key for the SAML attribute friendly name (alternative to {@link #SAML_ATTRIBUTE_NAME}). */
  public static final String SAML_ATTRIBUTE_FRIENDLY_NAME = "attribute.friendly.name";

  /** Configuration key for the user session note name. */
  public static final String SESSION_NOTE_CONFIG = "session.note";

  /**
   * Default user session note key written by this mapper. Used by {@link SessionNoteClaimMapper}
   * as its default read key.
   */
  public static final String DEFAULT_SESSION_NOTE = "transient_personal_identity_number";

  private static final String[] COMPATIBLE_PROVIDERS = { SAMLIdentityProviderFactory.PROVIDER_ID };

  private static final Set<IdentityProviderSyncMode> SYNC_MODES =
      new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    final List<ProviderConfigProperty> props = new ArrayList<>();

    final ProviderConfigProperty attrNameProp = new ProviderConfigProperty();
    attrNameProp.setName(SAML_ATTRIBUTE_NAME);
    attrNameProp.setLabel("Attribute Name");
    attrNameProp.setHelpText(
        "Name of the SAML assertion attribute to read (e.g. urn:oid:1.2.752.29.4.13 for "
            + "Swedish personnummer). Leave blank and use Friendly Name instead if preferred.");
    attrNameProp.setType(ProviderConfigProperty.STRING_TYPE);
    props.add(attrNameProp);

    final ProviderConfigProperty attrFriendlyProp = new ProviderConfigProperty();
    attrFriendlyProp.setName(SAML_ATTRIBUTE_FRIENDLY_NAME);
    attrFriendlyProp.setLabel("Friendly Name");
    attrFriendlyProp.setHelpText(
        "Friendly name of the SAML attribute (alternative to Attribute Name). "
            + "Attribute Name takes precedence when both are configured.");
    attrFriendlyProp.setType(ProviderConfigProperty.STRING_TYPE);
    props.add(attrFriendlyProp);

    final ProviderConfigProperty sessionNoteProp = new ProviderConfigProperty();
    sessionNoteProp.setName(SESSION_NOTE_CONFIG);
    sessionNoteProp.setLabel("User Session Note");
    sessionNoteProp.setHelpText(
        "Name of the user session note to which the SAML attribute value is written. "
            + "The note is transferred from the authentication session to the UserSessionModel "
            + "after login and can be read by OIDC protocol mappers during token generation. "
            + "When using multiple mapper instances (e.g. personnummer + coordination number), "
            + "configure both with the same note key.");
    sessionNoteProp.setType(ProviderConfigProperty.STRING_TYPE);
    sessionNoteProp.setDefaultValue(DEFAULT_SESSION_NOTE);
    props.add(sessionNoteProp);

    CONFIG_PROPERTIES = Collections.unmodifiableList(props);
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String[] getCompatibleProviders() {
    return COMPATIBLE_PROVIDERS;
  }

  @Override
  public boolean supportsSyncMode(final IdentityProviderSyncMode syncMode) {
    return SYNC_MODES.contains(syncMode);
  }

  @Override
  public String getDisplayType() {
    return "SAML Attribute to Session Note";
  }

  @Override
  public String getDisplayCategory() {
    return "Session Note Mapper";
  }

  @Override
  public String getHelpText() {
    return "Reads a configurable SAML assertion attribute and writes its value to a user session "
        + "note. Designed for transient proxy realms (doNotStoreUsers=true) where user-model "
        + "attributes do not survive beyond the current request. Pair with the "
        + "\"Session Note to Claim\" OIDC protocol mapper (or the built-in "
        + "\"User Session Note\" mapper) on the downstream client to emit the value as a token claim.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  /**
   * Reads the configured SAML attribute from the assertion and stores it as a user session note.
   * If the attribute is absent or blank, the method returns without writing any note.
   */
  @Override
  public void preprocessFederatedIdentity(
      final KeycloakSession session,
      final RealmModel realm,
      final IdentityProviderMapperModel mapperModel,
      final BrokeredIdentityContext context) {

    final String value = this.readAttribute(context, mapperModel);
    if (value == null || value.isBlank()) {
      LOG.debugf("SAML attribute '%s' not present in assertion for IdP '%s' — skipping session note",
          mapperModel.getConfig().get(SAML_ATTRIBUTE_NAME),
          context.getIdpConfig().getAlias());
      return;
    }

    final String noteKey = resolveNoteKey(mapperModel);
    context.getAuthenticationSession().setUserSessionNote(noteKey, value);
    LOG.debugf("Stored SAML attribute '%s' as user session note '%s' for IdP '%s'",
        mapperModel.getConfig().get(SAML_ATTRIBUTE_NAME), noteKey,
        context.getIdpConfig().getAlias());
  }

  /**
   * Also sets the attribute value as a user model attribute under the same key as the session note.
   *
   * <p>This is a belt-and-suspenders complement to {@link #preprocessFederatedIdentity}. In some
   * Keycloak deployments (specifically when {@code doNotStoreUsers=true} creates
   * {@code LightweightUserAdapter} instances) user-session-notes set on the
   * {@code AuthenticationSessionModel} are not transferred to the {@code UserSessionModel}'s
   * note map. The lightweight user's attributes are, however, reliably serialised into the
   * {@code keycloak.userModel} user-session note and remain accessible via
   * {@code userSession.getUser().getFirstAttribute(key)} during token generation.</p>
   */
  @Override
  public void importNewUser(
      final KeycloakSession session,
      final RealmModel realm,
      final UserModel user,
      final IdentityProviderMapperModel mapperModel,
      final BrokeredIdentityContext context) {
    this.setUserAttribute(user, mapperModel, context);
  }

  /**
   * Also sets the attribute value as a user model attribute under the same key as the session note.
   *
   * @see #importNewUser
   */
  @Override
  public void updateBrokeredUser(
      final KeycloakSession session,
      final RealmModel realm,
      final UserModel user,
      final IdentityProviderMapperModel mapperModel,
      final BrokeredIdentityContext context) {
    this.setUserAttribute(user, mapperModel, context);
  }

  private void setUserAttribute(
      final UserModel user,
      final IdentityProviderMapperModel mapperModel,
      final BrokeredIdentityContext context) {
    final String value = this.readAttribute(context, mapperModel);
    if (value == null || value.isBlank()) {
      return;
    }
    final String noteKey = resolveNoteKey(mapperModel);
    user.setSingleAttribute(noteKey, value);
    LOG.debugf("Set user attribute '%s' on lightweight user for IdP '%s'",
        noteKey, context.getIdpConfig().getAlias());
  }

  /**
   * Reads the first value of the configured SAML attribute from the brokered identity context.
   * Extracted as a protected method to allow overriding in tests without requiring SAML DOM types.
   *
   * @param context the brokered identity context
   * @param mapperModel the mapper configuration model
   * @return the attribute value, or {@code null} if not found
   */
  protected String readAttribute(
      final BrokeredIdentityContext context,
      final IdentityProviderMapperModel mapperModel) {

    final String attrName = mapperModel.getConfig().get(SAML_ATTRIBUTE_NAME);
    final String friendlyName = mapperModel.getConfig().get(SAML_ATTRIBUTE_FRIENDLY_NAME);
    final String lookupName = (attrName != null && !attrName.isBlank()) ? attrName : friendlyName;
    if (lookupName == null || lookupName.isBlank()) {
      return null;
    }

    final AssertionType assertion =
        (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
    if (assertion == null) {
      return null;
    }

    return assertion.getAttributeStatements().stream()
        .flatMap(stmt -> stmt.getAttributes().stream())
        .map(AttributeStatementType.ASTChoiceType::getAttribute)
        .filter(attr -> Objects.equals(attr.getName(), lookupName)
            || Objects.equals(attr.getFriendlyName(), lookupName))
        .flatMap(attr -> attr.getAttributeValue().stream())
        .filter(Objects::nonNull)
        .map(Object::toString)
        .findFirst()
        .orElse(null);
  }

  /**
   * Resolves the effective session note key from the mapper model config, falling back to
   * {@link #DEFAULT_SESSION_NOTE} when the config entry is absent or blank.
   *
   * @param mapperModel the mapper configuration model
   * @return the session note key to use
   */
  static String resolveNoteKey(final IdentityProviderMapperModel mapperModel) {
    final String key = mapperModel.getConfig().get(SESSION_NOTE_CONFIG);
    return (key != null && !key.isBlank()) ? key : DEFAULT_SESSION_NOTE;
  }

}
