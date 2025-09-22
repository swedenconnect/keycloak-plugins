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

import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.Organization;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.build.AttributeConsumingServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ContactPersonBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.LogoBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.OrganizationBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.RequestedAttributeBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.UIInfoBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Utility methods for working with SAML metadata.
 *
 * @author Martin Lindström
 */
public class MetadataUtils {

  public record RequestedAttributeConfig(String name, Boolean required) {
  }

  public record OrganizationConfig(LocalizedString names, LocalizedString displayNames, LocalizedString urls) {
  }

  public record ContactPersonConfig(
      String company,
      String givenName,
      String surname,
      String email,
      String telephoneNumber) {

  }

  public record UIInfoConfig(
      LocalizedString displayNames,
      LocalizedString descriptions,
      List<UIInfoLogo> logos
  ) {
    public record UIInfoLogo(String path, int height, int width) {
    }
  }

  public static UIInfo getUIInfoElement(final UIInfoConfig uiinfo, final String baseUri) {
    if (uiinfo == null) {
      return null;
    }
    return UIInfoBuilder.builder()
        .displayNames(uiinfo.displayNames())
        .descriptions(uiinfo.descriptions())
        .logos(getUiInfoLogos(uiinfo.logos, baseUri))
        .build();
  }

  private static List<Logo> getUiInfoLogos(final List<UIInfoConfig.UIInfoLogo> logos, final String baseUri) {
    if (logos == null) {
      return Collections.emptyList();
    }
    return logos.stream()
        .map(l -> LogoBuilder.logo(String.format("%s%s", baseUri, l.path), l.height,
            l.width))
        .collect(Collectors.toList());
  }

  public static Organization getOrganizationElement(final OrganizationConfig organization) {
    if (organization == null) {
      return null;
    }
    return OrganizationBuilder.builder()
        .organizationNames(organization.names)
        .organizationDisplayNames(organization.displayNames)
        .organizationURLs(organization.urls)
        .build();
  }

  public static List<ContactPerson> getContactPersonElements(
      final Map<ContactPersonTypeEnumeration, ContactPersonConfig> contactPersons) {
    if (contactPersons == null || contactPersons.isEmpty()) {
      return Collections.emptyList();
    }
    final List<ContactPerson> persons = new ArrayList<>();
    for (final Map.Entry<ContactPersonTypeEnumeration, ContactPersonConfig> e : contactPersons.entrySet()) {
      final ContactPersonBuilder b = ContactPersonBuilder.builder()
          .type(e.getKey())
          .company(e.getValue().company)
          .givenName(e.getValue().givenName)
          .surname(e.getValue().surname);

      Optional.ofNullable(e.getValue().email)
          .filter(email -> !email.isBlank())
          .ifPresent(b::emailAddresses);

      Optional.ofNullable(e.getValue().telephoneNumber)
          .filter(telephoneNumnber -> !telephoneNumnber.isBlank())
          .ifPresent(b::telephoneNumbers);

      persons.add(b.build());
    }
    return persons;
  }

  public static AttributeConsumingService getAttributeConsumingService(
      final List<LocalizedString> serviceNames, final List<RequestedAttributeConfig> requestedAttributes) {
    if ((serviceNames == null || serviceNames.isEmpty())
        && (requestedAttributes == null || requestedAttributes.isEmpty())) {
      return null;
    }
    final AttributeConsumingServiceBuilder builder = AttributeConsumingServiceBuilder.builder();

    builder.serviceNames(serviceNames);

    if (requestedAttributes != null) {
      builder.requestedAttributes(requestedAttributes.stream()
          .filter(ra -> ra.name != null)
          .map(ra -> RequestedAttributeBuilder.builder(ra.name).isRequired(ra.required).build())
          .collect(Collectors.toList()));
    }

    return builder.build();
  }

  private MetadataUtils() {
  }

}
