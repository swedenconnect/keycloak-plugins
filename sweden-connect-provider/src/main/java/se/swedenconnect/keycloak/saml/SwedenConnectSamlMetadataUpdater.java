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

import jakarta.enterprise.inject.spi.CDI;
import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v2.mdui.LogoType;
import org.keycloak.dom.saml.v2.metadata.ContactType;
import org.keycloak.dom.saml.v2.metadata.ContactTypeType;
import org.keycloak.dom.saml.v2.metadata.EndpointType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.ExtensionsType;
import org.keycloak.dom.saml.v2.metadata.IndexedEndpointType;
import org.keycloak.dom.saml.v2.metadata.LocalizedNameType;
import org.keycloak.dom.saml.v2.metadata.LocalizedURIType;
import org.keycloak.dom.saml.v2.metadata.OrganizationType;
import org.keycloak.dom.saml.v2.metadata.RequestedAttributeType;
import org.keycloak.dom.saml.v2.metadata.SPSSODescriptorType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmProvider;
import org.keycloak.protocol.saml.mappers.SamlMetadataDescriptorUpdater;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import se.swedenconnect.keycloak.oidc.AttributeToClaim;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Responsible for updating service provider metadata.
 *
 * @author Felix Hellman
 */
public class SwedenConnectSamlMetadataUpdater implements Module, SamlMetadataDescriptorUpdater {

  private static final Logger log = Logger.getLogger(SwedenConnectSamlMetadataUpdater.class);

  public static final String PROPERTY_PUBLISHING_PATH = "property.publishing.path";

  public static final String ATTRIBUTE_SAML_ENTITY_CATEGORIES = "attribute.entity.key";

  public static final String ATTRIBUTE_TECHNICAL_CONTACT_EMAIL = "attribute.contact.technical.email";

  public static final String ATTRIBUTE_SUPPORT_CONTACT_EMAIL = "attribute.contact.support.email";

  public static final String ATTRIBUTE_ORG_SV_NAME = "attribute.org.sv.name";

  public static final String ATTRIBUTE_ORG_SV_URI = "attribute.org.sv.uri";

  public static final String ATTRIBUTE_ORG_EN_NAME = "attribute.org.en.name";

  public static final String ATTRIBUTE_ORG_EN_URI = "attribute.org.en.uri";

  public static final String ATTRIBUTE_UI_INFO_DISPLAYNAME = "attribute.ui.displayname";

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {

    final ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();

    builder.property()
        .name(ATTRIBUTE_SAML_ENTITY_CATEGORIES)
        .helpText("SAML Entity Categories, key value is ignored")
        .label("SAML Entity Categories")
        .type(ProviderConfigProperty.MAP_TYPE)
        .add();

    builder.property()
        .name(ATTRIBUTE_UI_INFO_DISPLAYNAME)
        .required(true)
        .helpText("Display Name for the UIInfo extension. Add country code as key, e.g., \"sv\" - \"Exempelklienten\". "
            + "Swedish is mandatory and English is recommended.")
        .label("UI Info Display Name")
        .type(ProviderConfigProperty.MAP_TYPE)
        .add();

    builder.property()
        .name(ATTRIBUTE_TECHNICAL_CONTACT_EMAIL)
        .required(true)
        .helpText("Email of technical contact person")
        .label("Technical Contact Person (email)")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add();

    builder.property()
        .name(ATTRIBUTE_SUPPORT_CONTACT_EMAIL)
        .required(true)
        .helpText("Email of support contact person")
        .label("Support Contact Person (email)")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add();

    builder.property()
        .name(ATTRIBUTE_ORG_SV_NAME)
        .required(true)
        .helpText("Organization Name (SV)")
        .label("Organization Name (SV)")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add();

    builder.property()
        .name(ATTRIBUTE_ORG_SV_URI)
        .required(true)
        .helpText("Organization URI (SV)")
        .label("Organization URI (SV)")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add();

    builder.property()
        .name(ATTRIBUTE_ORG_EN_NAME)
        .required(false)
        .helpText("Organization Name (EN)")
        .label("Organization Name (EN)")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add();

    builder.property()
        .name(ATTRIBUTE_ORG_EN_URI)
        .required(false)
        .helpText("Organization URI (EN)")
        .label("Organization URI (EN)")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add();

    return builder.build();
  }

  @Override
  public void updateMetadata(
      final IdentityProviderMapperModel mapperModel,
      final EntityDescriptorType entityDescriptor) {

    final KeycloakSession session = CDI.current().select(KeycloakSession.class).get();

    final Set<RealmProvider> realmProviders = session.getAllProviders(RealmProvider.class);
    final RealmProvider realmProvider = realmProviders.stream().findFirst().get();

    final List<IndexedEndpointType> assertionConsumers = new ArrayList<>();
    realmProvider.getRealmsStream()
        .forEach(r -> {
          r.getIdentityProvidersStream()
              .filter(idp -> idp.getConfig().containsKey("entityId"))
              .filter(idp -> idp.getConfig().get("entityId").equals(entityDescriptor.getEntityID()))
              .forEach(idp -> {
                final int index = Integer.parseInt(idp.getConfig().get("attributeConsumingServiceIndex"));
                final IndexedEndpointType assertionConsumer = new IndexedEndpointType(
                    URI.create("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
                    URI.create("%srealms/%s/broker/%s/endpoint"
                        .formatted(
                            session.getContext().getUri().getBaseUri().toString(),
                            r.getName(),
                            idp.getAlias()
                        )
                    )
                );
                assertionConsumer.setIndex(index);
                assertionConsumers.add(assertionConsumer);
              });
        });

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

    final SPSSODescriptorType spDescriptor = entityDescriptor.getChoiceType().getFirst()
        .getDescriptors().getFirst()
        .getSpDescriptor();

    assertionConsumers.forEach(
        endpt -> {
          final boolean exists = spDescriptor.getSingleLogoutService().stream()
              .anyMatch(internal -> internal.getLocation().equals(endpt.getLocation()));
          if (!exists) {
            spDescriptor.addSingleLogoutService(new EndpointType(
                URI.create("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
                endpt.getLocation()
            ));
          }
        });

    assertionConsumers
        .forEach(endpt -> {
          final boolean exists = spDescriptor.getAssertionConsumerService().stream()
              .anyMatch(internal -> internal.getLocation().equals(endpt.getLocation()));
          if (!exists) {
            spDescriptor.addAssertionConsumerService(endpt);
          }
        });

    entityDescriptor.getChoiceType().forEach(edtChoiceType -> {
      edtChoiceType.getDescriptors().forEach(edtDescriptorChoiceType -> {
        edtDescriptorChoiceType.getSpDescriptor()
            .getAttributeConsumingService().forEach(attributeConsumingServiceType -> {
              final LocalizedNameType serviceName = new LocalizedNameType("en");
              serviceName.setValue("sweden-connect");
              final List<LocalizedNameType> names = new ArrayList<>(attributeConsumingServiceType.getServiceName());
              names.forEach(attributeConsumingServiceType::removeServiceName);
              attributeConsumingServiceType.addServiceName(serviceName);
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
    this.addDisplayInfo(mapperModel, entityDescriptor);
  }

  private static LocalizedURIType createLocalizedUri(final String lang, final String uriValue) {
    final LocalizedURIType uri1 = new LocalizedURIType(lang);
    uri1.setValue(URI.create(uriValue));
    return uri1;
  }

  private static LocalizedNameType createLocalizedName(final String lang, final String value) {
    final LocalizedNameType ln = new LocalizedNameType(lang);
    ln.setValue(value);
    return ln;
  }

  private void addDisplayInfo(final IdentityProviderMapperModel mapperModel,
      final EntityDescriptorType entityDescriptor) {

    //Following code is included and should work but is currently not being displayed as metadata
    //Hard coded values will be removed when UI info is present in metadata.

    final SPSSODescriptorType ssoDescriptor = entityDescriptor.getChoiceType()
        .getFirst().getDescriptors()
        .getFirst().getSpDescriptor();

    final ExtensionsType extension = Optional.ofNullable(ssoDescriptor.getExtensions())
        .orElseGet(() -> {
          final ExtensionsType e = new ExtensionsType();
          ssoDescriptor.setExtensions(e);
          return e;
        });

    //    final UIInfoType uiInfo = new UIInfoType();

    final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(false);
    final Document document;
    try {
      document = factory.newDocumentBuilder().newDocument();
    }
    catch (final ParserConfigurationException e) {
      throw new IllegalStateException("Invalid configuration for document builder", e);
    }

    final Element element = document.createElementNS(
        "urn:oasis:names:tc:SAML:metadata:ui",
        "mdui:UIInfo");
    element.setAttributeNS(
        "http://www.w3.org/2000/xmlns/",
        "xmlns:mdui",
        "urn:oasis:names:tc:SAML:metadata:ui"
    );

    mapperModel.getConfigMap(ATTRIBUTE_UI_INFO_DISPLAYNAME).forEach((key, values) -> {
      if (key == null || !key.matches("[a-zA-Z]{2}")) {
        log.infov("Invalid UI display name - invalid language tag (%s)", key);
        return;
      }
      if (values == null || values.isEmpty()) {
        log.info("Invalid UI display name - no display name given");
        return;
      }
      final Element child = document.createElementNS("", "mdui:DisplayName");
      child.setAttribute("xml:lang", key.toLowerCase());
      child.setTextContent(values.getFirst());
      element.appendChild(child);
      //uiInfo.addDisplayName(createLocalizedName(key.toLowerCase(), values.getFirst()));
    });

    extension.addExtension(element);
/*
    final LogoType logo = new LogoType(256, 256);

    logo.setValue(URI.create(
        "https://swedenconnect.se/images/18.5b0eb5a018018072bd816a52/1646216790599/sweden-connect-logo-sv.svg"
    ));
    uiInfo.addLogo(logo);
    //    final LocalizedNameType displayName = new LocalizedNameType("sv");
    //    displayName.setValue("Keycloak Sweden Connect Plugin");
    //    uiInfo.addDisplayName(displayName);
    final LocalizedNameType description = new LocalizedNameType("sv");
    description.setValue("Keycloak Plugin for Sweden Connect");
    uiInfo.addDescription(description);

    extension.addExtension(uiInfo);
 */
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
    }
    catch (final ParserConfigurationException e) {
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
