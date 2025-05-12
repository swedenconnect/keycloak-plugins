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


import org.keycloak.broker.oidc.mappers.UserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * UserAttributeMapper for OIDC.
 *
 * @author Felix Hellman
 */
public class SwedenConnectOIDCAttributeMapper extends UserAttributeMapper {

  @Override
  public void preprocessFederatedIdentity(
      final KeycloakSession session,
      final RealmModel realm,
      final IdentityProviderMapperModel mapperModel,
      final BrokeredIdentityContext context) {

    final Map<String, Object> contextData = context.getContextData();
    final Map<String, Object> claims = new HashMap<>();
    final JsonWebToken validatedIdToken = (JsonWebToken) contextData.get("VALIDATED_ID_TOKEN");
    final JsonWebToken validatedAccessToken = (JsonWebToken) contextData.get("VALIDATED_ACCESS_TOKEN");
    claims.putAll(validatedIdToken.getOtherClaims());
    claims.putAll(validatedAccessToken.getOtherClaims());
    if (context.getIdpConfig().isTransientUsers()) {
      this.populateUserAttributes(context, claims);
    }
    this.populateSessionNotes(context, claims);

    super.preprocessFederatedIdentity(session, realm, mapperModel, context);
  }

  private void populateUserAttributes(
      final BrokeredIdentityContext context,
      final Map<String, Object> claims) {

    AttributeToClaim.ATTRIBUTE_MAPPINGS.forEach(claim -> {
      Optional.ofNullable(claims.get(claim.getOidcClaimName()))
          .filter(v -> !List.of(
              "urn:oid:1.2.752.201.3.11",
              "urn:oid:1.2.752.201.3.10",
              "urn:oid:1.2.752.201.3.13"
          ).contains(claim.getSamlAttributeName()))
          .ifPresent(value -> context.setUserAttribute(
                  claim.getSamlAttributeName(), (String) value
              )
          );
    });
  }

  private void populateSessionNotes(
      final BrokeredIdentityContext context,
      final Map<String, Object> claims) {

    AttributeToClaim.ATTRIBUTE_MAPPINGS.forEach(claim -> {
      Optional.ofNullable(claims.get(claim.getOidcClaimName()))
          .filter(v -> !List.of(
              "urn:oid:1.2.752.201.3.11",
              "urn:oid:1.2.752.201.3.10",
              "urn:oid:1.2.752.201.3.13"
          ).contains(claim.getSamlAttributeName()))
          .ifPresent(value -> context.setSessionNote(
                  claim.getSamlAttributeName(), (String) value
              )
          );
    });
  }

  @Override
  public String getId() {
    return "SwedenConnect-OP";
  }

  @Override
  public String getDisplayCategory() {
    return "Sweden Connect";
  }

  @Override
  public String getDisplayType() {
    return "SwedenConnect-OP";
  }

  @Override
  public String getHelpText() {
    return "OP Provider for Sweden Connect";
  }
}
