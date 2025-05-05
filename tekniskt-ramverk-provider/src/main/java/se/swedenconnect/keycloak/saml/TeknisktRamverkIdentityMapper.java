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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.AuthnContextType;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Responsible for mapping SAML attributes to session notes and user properties.
 *
 * @author Felix Hellman
 */
public class TeknisktRamverkIdentityMapper implements Module {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static final Logger log = Logger.getLogger(TeknisktRamverkIdentityMapper.class);

  /**
   * Attribute key for username attribute.
   */
  public static final String ATTRIBUTE_USERNAME_KEY = "attribute.username.key";

  /**
   * Processes identity of completed authentication.
   * @param mapperModel
   * @param context
   *
   */
  public void process(
      final IdentityProviderMapperModel mapperModel,
      final BrokeredIdentityContext context) {

    final AssertionType assertion = (AssertionType) context.getContextData().get("SAML_ASSERTION");

    this.populateSessionAttributes(context, assertion);
    this.setUserIdentity(mapperModel, context, assertion);
    this.setOtherUserProperties(context, assertion);

    assertion.getStatements().forEach(statement -> {
      if (statement instanceof AuthnStatementType authn) {
        final AuthnContextType.AuthnContextTypeSequence sequence = authn.getAuthnContext().getSequence();
        final String value = sequence.getClassRef().getValue().toString();
        context.setSessionNote("acr", value);
      }
    });
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    final ProviderConfigProperty property = new ProviderConfigProperty();
    property.setName(ATTRIBUTE_USERNAME_KEY);
    property.setLabel("Username Attribute");
    property.setHelpText("Username Attribute for this IDP");
    property.setType("List");
    property.setOptions(
        List.of(
            "urn:oid:1.2.752.29.4.13",
            "urn:oid:1.2.752.201.3.4",
            "urn:oid:1.2.752.29.6.2.1"
        )
    );
    property.setDefaultValue("urn:oid:1.2.752.29.4.13");
    return List.of(property);
  }

  private void setOtherUserProperties(final BrokeredIdentityContext context, final AssertionType assertion) {
    assertion.getAttributeStatements().stream()
        .flatMap(ast -> {
          return ast.getAttributes().stream();
        })
        .map(AttributeStatementType.ASTChoiceType::getAttribute)
        .forEach(value -> {
          if (value.getName().equals("urn:oid:2.5.4.4")) {
            context.setUserAttribute("lastName", (String) value.getAttributeValue().getFirst());
          }
          if (value.getName().equals("urn:oid:2.5.4.42")) {
            context.setUserAttribute("firstName", (String) value.getAttributeValue().getFirst());
          }
        });
  }

  private void setUserIdentity(
      final IdentityProviderMapperModel mapperModel,
      final BrokeredIdentityContext context,
      final AssertionType assertion) {

    String userIdentity = null;
    final Optional<AttributeType> userAttribute = assertion.getAttributeStatements().stream()
        .flatMap(ast -> {
          return ast.getAttributes().stream();
        })
        .map(AttributeStatementType.ASTChoiceType::getAttribute)
        .filter(attribute -> {
              return attribute.getName().equals(mapperModel.getConfig().get(ATTRIBUTE_USERNAME_KEY));
            }
        ).findFirst();

    if (userAttribute.isPresent()) {
      userIdentity = (String) userAttribute.get().getAttributeValue().getFirst();
      context.setUserAttribute("username", userIdentity);
    }
  }

  private void populateSessionAttributes(final BrokeredIdentityContext context, final AssertionType assertion) {
    final Map<String, Object> attributes = new HashMap<>();
    assertion.getAttributeStatements().forEach(ast -> {
      ast.getAttributes().forEach(astc -> {
        attributes.put(astc.getAttribute().getName(), astc.getAttribute().getAttributeValue());
      });
    });
    try {
      final String json = MAPPER.writer().writeValueAsString(attributes);
      context.setSessionNote("SAML_ATTRIBUTES_JSON", json);
    } catch (final JsonProcessingException e) {
      log.errorf("Failed to serialize SAML attributes. Attributes:%s", attributes);
    }
  }
}
