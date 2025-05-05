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

import org.keycloak.dom.saml.v2.mdui.LogoType;
import org.keycloak.dom.saml.v2.mdui.UIInfoType;
import org.keycloak.dom.saml.v2.metadata.ContactType;
import org.keycloak.dom.saml.v2.metadata.ContactTypeType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.ExtensionsType;
import org.keycloak.dom.saml.v2.metadata.LocalizedNameType;
import org.keycloak.dom.saml.v2.metadata.LocalizedURIType;
import org.keycloak.dom.saml.v2.metadata.OrganizationType;
import org.keycloak.dom.saml.v2.metadata.RequestedAttributeType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.protocol.saml.mappers.SamlMetadataDescriptorUpdater;
import org.keycloak.provider.ProviderConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import se.swedenconnect.keycloak.oidc.AttributeToClaim;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.net.URI;
import java.util.List;
import java.util.Optional;

/**
 * Responsible for updating service provider metadata.
 *
 * @author Felix Hellman
 */
public class SwedenConnectSamlMetadataUpdater implements Module, SamlMetadataDescriptorUpdater {

  /**
   * Attribute key for entity categories.
   */
  public static final String ATTRIBUTE_SAML_ENTITY_CATEGORIES = "attribute.entity.key";

  public static final String ATTRIBUTE_TECHNICAL_CONTACT_EMAIL = "attribute.contact.technical.email";

  public static final String ATTRIBUTE_SUPPORT_CONTACT_EMAIL = "attribute.contact.support.email";

  public static final String ATTRIBUTE_ORG_SV_NAME = "attribute.org.sv.name";

  public static final String ATTRIBUTE_ORG_SV_URI = "attribute.org.sv.uri";

  public static final String ATTRIBUTE_ORG_EN_NAME = "attribute.org.en.name";

  public static final String ATTRIBUTE_ORG_EN_URI = "attribute.org.en.uri";

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    final ProviderConfigProperty extensionsProperty = new ProviderConfigProperty();
    extensionsProperty.setType(ProviderConfigProperty.MAP_TYPE);
    extensionsProperty.setName(ATTRIBUTE_SAML_ENTITY_CATEGORIES);
    extensionsProperty.setHelpText("SAML Entity Categories, key value is ignored");
    extensionsProperty.setLabel("SAML Entity Categories");

    final ProviderConfigProperty contactPersonProperty = new ProviderConfigProperty();
    contactPersonProperty.setName(ATTRIBUTE_TECHNICAL_CONTACT_EMAIL);
    contactPersonProperty.setRequired(true);
    contactPersonProperty.setHelpText("Email of technical contact person");
    contactPersonProperty.setLabel("Technical Contact Person");
    contactPersonProperty.setType(ProviderConfigProperty.STRING_TYPE);

    final ProviderConfigProperty contactSupportPersonProperty = new ProviderConfigProperty();
    contactSupportPersonProperty.setName(ATTRIBUTE_SUPPORT_CONTACT_EMAIL);
    contactSupportPersonProperty.setRequired(true);
    contactSupportPersonProperty.setHelpText("Email of support contact person");
    contactSupportPersonProperty.setLabel("Support Contact Person");
    contactSupportPersonProperty.setType(ProviderConfigProperty.STRING_TYPE);

    final ProviderConfigProperty orgNameSvProperty = new ProviderConfigProperty();
    orgNameSvProperty.setName(ATTRIBUTE_ORG_SV_NAME);
    orgNameSvProperty.setRequired(true);
    orgNameSvProperty.setHelpText("Organization Name (SV)");
    orgNameSvProperty.setLabel("Organization Name (SV)");
    orgNameSvProperty.setType(ProviderConfigProperty.STRING_TYPE);

    final ProviderConfigProperty orgURISvProperty = new ProviderConfigProperty();
    orgURISvProperty.setName(ATTRIBUTE_ORG_SV_URI);
    orgURISvProperty.setRequired(true);
    orgURISvProperty.setHelpText("Organization URI (SV)");
    orgURISvProperty.setLabel("Organization URI (SV)");
    orgURISvProperty.setType(ProviderConfigProperty.STRING_TYPE);

    final ProviderConfigProperty orgNameEnProperty = new ProviderConfigProperty();
    orgNameEnProperty.setName(ATTRIBUTE_ORG_EN_NAME);
    orgNameEnProperty.setRequired(false);
    orgNameEnProperty.setHelpText("Organization Name (EN)");
    orgNameEnProperty.setLabel("Organization Name (EN)");
    orgNameEnProperty.setType(ProviderConfigProperty.STRING_TYPE);

    final ProviderConfigProperty orgURIEnProperty = new ProviderConfigProperty();
    orgURIEnProperty.setName(ATTRIBUTE_ORG_EN_URI);
    orgURIEnProperty.setRequired(false);
    orgURIEnProperty.setHelpText("Organization URI (EN)");
    orgURIEnProperty.setLabel("Organization URI (EN)");
    orgURIEnProperty.setType(ProviderConfigProperty.STRING_TYPE);

    return List.of(
        extensionsProperty,
        contactPersonProperty,
        contactSupportPersonProperty,
        orgNameSvProperty,
        orgURISvProperty,
        orgNameEnProperty,
        orgURIEnProperty
    );
  }

  @Override
  public void updateMetadata(
      final IdentityProviderMapperModel mapperModel,
      final EntityDescriptorType entityDescriptor) {

    entityDescriptor.setOrganization(new OrganizationType());

    Optional.ofNullable(mapperModel.getConfig().get(ATTRIBUTE_ORG_EN_NAME)).ifPresent(orgName -> {
      entityDescriptor.getOrganization().addOrganizationName(createLocalizedName("en", orgName));
      entityDescriptor.getOrganization().addOrganizationDisplayName(createLocalizedName("en", orgName));
    });

    Optional.ofNullable(mapperModel.getConfig().get(ATTRIBUTE_ORG_SV_NAME)).ifPresent(orgName -> {
      entityDescriptor.getOrganization().addOrganizationName(createLocalizedName("sv", orgName));
      entityDescriptor.getOrganization().addOrganizationDisplayName(createLocalizedName("sv", orgName));

      Optional.ofNullable(mapperModel.getConfig().get(ATTRIBUTE_SUPPORT_CONTACT_EMAIL)).ifPresent(email -> {
        final ContactType contact = new ContactType(ContactTypeType.SUPPORT);
        entityDescriptor.addContactPerson(contact);
        contact.addEmailAddress(email);
        contact.setCompany(orgName);
      });

      Optional.ofNullable(mapperModel.getConfig().get(ATTRIBUTE_TECHNICAL_CONTACT_EMAIL)).ifPresent(email -> {
        final ContactType contact = new ContactType(ContactTypeType.TECHNICAL);
        entityDescriptor.addContactPerson(contact);
        contact.addEmailAddress(email);
        contact.setCompany(orgName);
      });
    });

    Optional.ofNullable(mapperModel.getConfig().get(ATTRIBUTE_ORG_EN_URI)).ifPresent(uri -> {
      entityDescriptor.getOrganization().addOrganizationURL(createLocalizedUri("en", uri));
    });

    Optional.ofNullable(mapperModel.getConfig().get(ATTRIBUTE_ORG_SV_URI)).ifPresent(uri -> {
      entityDescriptor.getOrganization().addOrganizationURL(createLocalizedUri("sv", uri));
    });

    entityDescriptor.getChoiceType().forEach(edtChoiceType -> {
      edtChoiceType.getDescriptors().forEach(edtDescriptorChoiceType -> {
        edtDescriptorChoiceType.getSpDescriptor()
            .getAttributeConsumingService().forEach(attributeConsumingServiceType -> {
              AttributeToClaim.ATTRIBUTE_MAPPINGS.forEach(r -> {
                attributeConsumingServiceType
                    .addRequestedAttribute(
                        new RequestedAttributeType(r.getSamlAttributeName())
                    );
              });
            });
      });
    });


    final List<String> entityCategories = mapperModel
        .getConfigMap(ATTRIBUTE_SAML_ENTITY_CATEGORIES).values().stream()
        .map(List::getFirst)
        .toList();

    this.addEntityCategories(entityDescriptor, entityCategories);
    this.addDisplayInfo(entityDescriptor);
  }

  private static LocalizedURIType createLocalizedUri(final String lang, final String uriValue) {
    final LocalizedURIType uri1 = new LocalizedURIType(lang);
    uri1.setValue(URI.create(uriValue));
    return uri1;
  }

  private static LocalizedNameType createLocalizedName(final String lang, final String value) {
    final LocalizedNameType english = new LocalizedNameType(lang);
    english.setValue(value);
    return english;
  }

  private void addDisplayInfo(final EntityDescriptorType entityDescriptor) {
    //Following code is included and should work but is currently not being displayed as metadata
    //Hard coded values will be removed when UI info is present in metadata.
    final ExtensionsType extension = new ExtensionsType();

    entityDescriptor.getChoiceType()
        .getFirst().getDescriptors()
        .getFirst().getSpDescriptor()
        .setExtensions(extension);

    final UIInfoType uiInfo = new UIInfoType();
    extension.addExtension(uiInfo);

    final LogoType logo = new LogoType(256, 256);

    logo.setValue(URI.create(
        "https://swedenconnect.se/images/18.5b0eb5a018018072bd816a52/1646216790599/sweden-connect-logo-sv.svg"
    ));
    uiInfo.addLogo(logo);
    final LocalizedNameType displayName = new LocalizedNameType("sv");
    displayName.setValue("Keycloak Sweden Connect Plugin");
    uiInfo.addDisplayName(displayName);
    final LocalizedNameType description = new LocalizedNameType("sv");
    description.setValue("Keycloak Plugin for Sweden Connect");
    uiInfo.addDescription(description);
  }

  private void addEntityCategories(
      final EntityDescriptorType entityDescriptor,
      final List<String> entityCategories) {

    final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(false);
    final Document document;
    try {
      document = factory.newDocumentBuilder()
          .newDocument();
    } catch (final ParserConfigurationException e) {
      throw new IllegalStateException("Invalid configuration for document builder", e);
    }

    final Element element = document
        .createElementNS(
            "urn:oasis:names:tc:SAML:metadata:attribute",
            "mdattr:EntityAttributes"
        );
    element.setAttributeNS(
        "http://www.w3.org/2000/xmlns/",
        "xmlns:mdattr",
        "urn:oasis:names:tc:SAML:metadata:attribute"
    );
    final ExtensionsType extensions = new ExtensionsType();
    entityDescriptor.setExtensions(extensions);
    extensions.addExtension(element);
    final Element attribute = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml2:Attribute");
    attribute.setAttributeNS(
        "http://www.w3.org/2000/xmlns/",
        "xmlns:saml2",
        "urn:oasis:names:tc:SAML:2.0:assertion"
    );
    attribute.setAttributeNS(
        "",
        "Name",
        "http://macedir.org/entity-category"
    );
    attribute.setAttributeNS(
        "",
        "NameFormat",
        "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    );
    element.appendChild(attribute);

    entityCategories.forEach(entityCategory -> {
      final Element child = document.createElementNS(
          "",
          "saml2:AttributeValue"
      );
      child.setAttributeNS(
          "http://www.w3.org/2000/xmlns/",
          "xmlns:xsd",
          "http://www.w3.org/2001/XMLSchema"
      );
      child.setAttributeNS("http://www.w3.org/2000/xmlns/",
          "xmlns:xsi",
          "http://www.w3.org/2001/XMLSchema-instance"
      );
      child.setAttributeNS(
          "http://www.w3.org/2001/XMLSchema-instance",
          "xsi:type",
          "xsd:string"
      );
      child.setTextContent(entityCategory);
      attribute.appendChild(child);
    });
  }
}
