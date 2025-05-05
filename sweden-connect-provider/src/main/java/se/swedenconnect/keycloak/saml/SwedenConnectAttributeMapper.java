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

package se.swedenconnect.keycloak.saml;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.mappers.UserAttributeMapper;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;
import java.util.stream.Stream;

/**
 * SAML SP/IDP proxy {@link UserAttributeMapper} for implementing Sweden Connect Attribute Specification.
 *
 * @author Felix Hellman
 */
public class SwedenConnectAttributeMapper extends UserAttributeMapper {

  private final SwedenConnectIdentityMapper mapper = new SwedenConnectIdentityMapper();
  private final SwedenConnectSamlMetadataUpdater metadataUpdater = new SwedenConnectSamlMetadataUpdater();

  @Override
  public void updateMetadata(
      final IdentityProviderMapperModel mapperModel,
      final EntityDescriptorType entityDescriptor) {

    this.metadataUpdater.updateMetadata(mapperModel, entityDescriptor);
    super.updateMetadata(mapperModel, entityDescriptor);
  }

  @Override
  public void preprocessFederatedIdentity(
      final KeycloakSession session,
      final RealmModel realm,
      final IdentityProviderMapperModel mapperModel,
      final BrokeredIdentityContext context) {
    this.mapper.process(mapperModel, context);
    super.preprocessFederatedIdentity(session, realm, mapperModel, context);
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return Stream.concat(
        this.mapper.getConfigProperties().stream(),
        this.metadataUpdater.getConfigProperties().stream()
    ).toList();
  }

  @Override
  public String getId() {
    return "Sweden-Connect";
  }

  @Override
  public String getDisplayType() {
    return "Sweden Connect";
  }

  @Override
  public String getDisplayCategory() {
    return "Identity Mapper & Metadata Updater";
  }
}
