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
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * An OIDC identity provider mapper that reads a claim from the validated id-token and overrides
 * the brokered identity's ID ({@code identity_provider_identity}) with its value.
 *
 * <p>Keycloak's built-in {@code OIDCIdentityProvider.extractIdentity} always uses the {@code sub}
 * claim as the broker identity ID, regardless of any {@code principalType=ATTRIBUTE} /
 * {@code principalAttribute} configuration. For a transient proxy realm (doNotStoreUsers=true),
 * the {@code sub} is a fresh {@code lightweight-&lt;UUID&gt;} per session, causing
 * {@code ModelDuplicateException} on second logins.</p>
 *
 * <p>This mapper runs <em>after</em> {@code extractIdentity} has populated the
 * {@link BrokeredIdentityContext} and calls both {@link BrokeredIdentityContext#setId(String)} and
 * {@link BrokeredIdentityContext#setUsername(String)} with the configured claim value, replacing
 * the ephemeral {@code sub} / {@code lightweight-&lt;UUID&gt;} username with a stable identifier
 * such as a Swedish personal identity number.</p>
 *
 * <p>Setting the username to the same stable value is required for the Keycloak
 * "Automatically set existing user" First Broker Login authenticator to locate a pre-provisioned
 * orgiam user by personal identity number (when {@code pnr-userids=true} is configured in
 * iam-admin-app) and link the federated identity to it, without creating a duplicate account.</p>
 *
 * <p>Configure this mapper on the orgiam OIDC identity provider that connects to the Transient
 * realm, with {@code claim.name = personalIdentityNumber} (the dot-free claim emitted by
 * {@link SessionNoteClaimMapper}).</p>
 *
 * @author David Goldring
 */
public class OidcClaimToBrokerIdMapper extends AbstractIdentityProviderMapper {

  private static final Logger LOG = Logger.getLogger(OidcClaimToBrokerIdMapper.class);

  /** Provider ID used to reference this mapper in Keycloak configuration. */
  public static final String PROVIDER_ID = "oidc-claim-to-broker-id-mapper";

  /** Configuration key for the claim name to read from the id-token. */
  public static final String CLAIM_NAME_CONFIG = "claim.name";

  /** Default claim name — matches {@link SessionNoteClaimMapper#DEFAULT_CLAIM_NAME}. */
  public static final String DEFAULT_CLAIM_NAME = SessionNoteClaimMapper.DEFAULT_CLAIM_NAME;

  private static final String[] COMPATIBLE_PROVIDERS = { "oidc", "keycloak-oidc" };

  private static final Set<IdentityProviderSyncMode> SYNC_MODES =
      new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    final List<ProviderConfigProperty> props = new ArrayList<>();

    final ProviderConfigProperty claimProp = new ProviderConfigProperty();
    claimProp.setName(CLAIM_NAME_CONFIG);
    claimProp.setLabel("Claim Name");
    claimProp.setHelpText(
        "Name of the claim in the validated id-token to use as the broker identity ID "
            + "(identity_provider_identity). Must match the claim emitted by the "
            + "\"Session Note to Claim\" protocol mapper on the OIDC client in the transient "
            + "realm. Use a dot-free name (e.g. personalIdentityNumber) to avoid Keycloak's "
            + "claim-path splitting.");
    claimProp.setType(ProviderConfigProperty.STRING_TYPE);
    claimProp.setDefaultValue(DEFAULT_CLAIM_NAME);
    props.add(claimProp);

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
    return "OIDC Claim to Broker Identity ID";
  }

  @Override
  public String getDisplayCategory() {
    return "Broker Identity Override";
  }

  @Override
  public String getHelpText() {
    return "Reads a claim from the validated id-token and overrides the brokered identity's "
        + "identity_provider_identity with its value. Use this on an OIDC identity provider "
        + "that fronts a transient (doNotStoreUsers=true) realm to replace the ephemeral "
        + "lightweight-<UUID> sub with a stable identifier such as a personal identity number. "
        + "Pair with the \"Session Note to Claim\" OIDC protocol mapper in the transient realm "
        + "that emits the identity as a dot-free claim (e.g. personalIdentityNumber).";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  /**
   * Reads the configured claim from the validated id-token and calls
   * {@link BrokeredIdentityContext#setId(String)} to replace the ephemeral {@code sub}.
   */
  @Override
  public void preprocessFederatedIdentity(
      final KeycloakSession session,
      final RealmModel realm,
      final IdentityProviderMapperModel mapperModel,
      final BrokeredIdentityContext context) {

    final String claimName = resolveClaimName(mapperModel);
    final String value = this.readClaimFromIdToken(context, claimName);

    if (value == null || value.isBlank()) {
      LOG.warnf("Claim '%s' absent in id-token from IdP '%s' — broker identity ID not overridden; "
              + "second logins will likely fail with ModelDuplicateException",
          claimName, context.getIdpConfig().getAlias());
      return;
    }

    LOG.debugf("Overriding broker identity ID and username with claim '%s'='%s' for IdP '%s'",
        claimName, value, context.getIdpConfig().getAlias());
    context.setId(value);
    context.setUsername(value);
  }

  /**
   * Also, override on update so subsequent logins resolve correctly.
   */
  @Override
  public void updateBrokeredUser(
      final KeycloakSession session,
      final RealmModel realm,
      final UserModel user,
      final IdentityProviderMapperModel mapperModel,
      final BrokeredIdentityContext context) {
    this.preprocessFederatedIdentity(session, realm, mapperModel, context);
  }

  /**
   * Reads the claim value from the validated id-token stored in the brokered identity context.
   */
  private String readClaimFromIdToken(
      final BrokeredIdentityContext context,
      final String claimName) {
    final Object tokenObj = context.getContextData().get(OIDCIdentityProvider.VALIDATED_ID_TOKEN);
    if (tokenObj instanceof JsonWebToken idToken) {
      final Object claim = idToken.getOtherClaims().get(claimName);
      if (claim != null) {
        return claim.toString();
      }
    }
    return null;
  }

  /**
   * Resolves the effective claim name from the mapper config, falling back to
   * {@link #DEFAULT_CLAIM_NAME} when absent or blank.
   *
   * @param mapperModel the mapper configuration model
   * @return the claim name to use
   */
  static String resolveClaimName(final IdentityProviderMapperModel mapperModel) {
    final String name = mapperModel.getConfig().get(CLAIM_NAME_CONFIG);
    return (name != null && !name.isBlank()) ? name : DEFAULT_CLAIM_NAME;
  }

}
