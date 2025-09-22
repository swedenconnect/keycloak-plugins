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

import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.UsageType;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.build.AssertionConsumerServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OidcToSamlMetadataFactory {
  public static EntityDescriptor createMetadata(
      final KeycloakSession session,
      final ClientRepresentation clientRepresentation) {

    final List<AssertionConsumerService> acs = new ArrayList<>();
    final URI baseUri = session.getContext().getUri().getBaseUri();
    acs.add(AssertionConsumerServiceBuilder.builder()
        .binding(SAMLConstants.SAML2_POST_BINDING_URI)
        .location(String.format("%s/saml2/sign", baseUri.toString()))
        .isDefault(true)
        .build());

    final SamlConfiguration config = createConfig(session, clientRepresentation);


    final List<String> entityCategories = new ArrayList<>();
    entityCategories.addAll(List.of()); // TODO map client to entity category

    return EntityDescriptorBuilder.builder()
        .entityID(clientRepresentation.getClientId())
        .extensions(ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(entityCategories)
                .build())
            .build())
        .ssoDescriptor(SPSSODescriptorBuilder.builder()
            .authnRequestsSigned(true)
            .wantAssertionsSigned(true)
            .extensions(ExtensionsBuilder.builder()
                .extension(MetadataUtils.getUIInfoElement(
                    config.uiInfoConfig,
                    config.baseUri))
                .build())
            .keyDescriptors(
                KeyDescriptorBuilder.builder()
                    .use(UsageType.SIGNING)
                    .keyName("Signing")
                    .certificate(config.signCertificate)
                    .build(),
                KeyDescriptorBuilder.builder()
                    .use(UsageType.ENCRYPTION)
                    .keyName("Encryption")
                    .certificate(config.encryptionCertificate)
                    .encryptionMethodsExt(config.encryptionMethods)
                    .build())
            .nameIDFormats(NameID.PERSISTENT, NameID.TRANSIENT)
            .attributeConsumingServices(MetadataUtils.getAttributeConsumingService(
                config.servicesNames,
                config.requestedAttributeConfigs
                ))
            .assertionConsumerServices(acs)
            .build())
        .organization(MetadataUtils.getOrganizationElement(config.organizationConfig))
        .contactPersons(MetadataUtils.getContactPersonElements(config.contactPersons))
        .build();
  }

  private record SamlConfiguration(
      Map<ContactPersonTypeEnumeration, MetadataUtils.ContactPersonConfig> contactPersons,
      MetadataUtils.OrganizationConfig organizationConfig,
      String baseUri,
      MetadataUtils.UIInfoConfig uiInfoConfig,
      List<LocalizedString> servicesNames,
      List<MetadataUtils.RequestedAttributeConfig> requestedAttributeConfigs,
      List<EncryptionMethod> encryptionMethods,
      X509Certificate signCertificate,
      X509Certificate encryptionCertificate
  ) {}

  private static SamlConfiguration createConfig(final KeycloakSession keycloakSession,
                                                final ClientRepresentation representation) {

    final String technicalContactPerson = representation.getAttributes().get("TECHNICAL_CONTACT_PERSON");
    final String orgNameSv = representation.getAttributes().get("ORG_NAME#SV");
    final LocalizedString orgNames = new LocalizedString(orgNameSv, "sv");

    final String displayNameSv = representation.getAttributes().get("ORG_DISPLAY_NAME#SV");
    final LocalizedString displayName = new LocalizedString(displayNameSv, "sv");

    final String orgUriSv = representation.getAttributes().get("ORG_URI#SV");
    final LocalizedString orgUri = new LocalizedString(orgUriSv, "sv");

    final MetadataUtils.OrganizationConfig organizationConfig = new MetadataUtils.OrganizationConfig(
        orgNames, displayName ,orgUri
    );

    new MetadataUtils.UIInfoConfig();

    return new SamlConfiguration(
        Map.of(ContactPersonTypeEnumeration.TECHNICAL, technicalContactPerson),
        organizationConfig,
        keycloakSession.getContext().getUri().getBaseUri().toString(),

        //TODO map baseUri
        //TODO map UIconfig
        //TODO map servicesNames
        //TODO map RequestedAttributeConfig
        //TODO map Encryption method
        //TODO load signCertificate
        //TODO load encryptionCertificate
    )
  }
}
