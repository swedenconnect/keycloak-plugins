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


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.mappers.UserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;
import se.swedenconnect.keycloak.saml.SwedenConnectIdentityMapper;

import java.util.*;


/**
 * UserAttributeMapper for OIDC.
 * Reads claims from underlying OP Access and ID Token and populates session notes
 * keyed with their respective SAML attribute name. <br/>
 * E.g. family_name gets saved with the "urn:oid:2.5.4.4" key.
 * This makes the {@link OIDCMapper} reusable for OIDC.
 *
 * @author Felix Hellman
 */
public class SwedenConnectOIDCAttributeMapper extends UserAttributeMapper {
  private static final Logger log = Logger.getLogger(SwedenConnectOIDCAttributeMapper.class);

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
    final ObjectNode validatedUserInfoToken = (ObjectNode) contextData.get("UserInfo");

    if(validatedIdToken != null) {
      final Iterator<Map.Entry<String, JsonNode>> fields = validatedUserInfoToken.fields();
      while (fields.hasNext()) {
        final Map.Entry<String, JsonNode> entry = fields.next();
        claims.put(entry.getKey(), entry.getValue().asText());
      }
    } else {
      log.info("There is no user_info data, make sure that user_info fetch is enabled");
    }

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
//
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
    return "Sweden-Connect-OP";
  }

  @Override
  public String getDisplayCategory() {
    return "Sweden Connect";
  }

  @Override
  public String getDisplayType() {
    return "Sweden-Connect ";
  }

  @Override
  public String getHelpText() {
    return "OP Provider for Sweden Connect";
  }

  @Override
  public List<ProviderConfigProperty> getConfigMetadata() {
    return List.of();
  }
}
