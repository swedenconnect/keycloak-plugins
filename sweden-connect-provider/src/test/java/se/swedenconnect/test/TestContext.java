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

package se.swedenconnect.test;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.models.IdentityProviderModel;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class TestContext extends BrokeredIdentityContext {

  private final Map<String, String> samlAttributes;

  public TestContext(final Map<String, String> samlAttributes) {
    super("TEST-ID", new IdentityProviderModel());
    this.samlAttributes = samlAttributes;
    final AssertionType assertionType = Mockito.mock(AssertionType.class);
    final HashSet<AttributeStatementType> hashSet = new HashSet<>();
    Mockito.when(assertionType.getAttributeStatements()).thenReturn(hashSet);
    samlAttributes.keySet().forEach(atr -> {
      final AttributeStatementType ast = new AttributeStatementType();
      final AttributeType attribute = new AttributeType(atr);
      attribute.addAttributeValue(samlAttributes.get(atr));
      ast.addAttribute(new AttributeStatementType.ASTChoiceType(attribute));
      hashSet.add(ast);
    });
    contextData.put("SAML_ASSERTION", assertionType);
  }

  public Map<String, String> getSamlAttributes() {
    return samlAttributes;
  }

  private final Map<String, Object> contextData = new HashMap<>();
  private final Map<String, String> sessionNotes = new HashMap<>();

  @Override
  public Map<String, Object> getContextData() {
    return contextData;
  }

  public Map<String, String> getSessionNotes() {
    return sessionNotes;
  }

  @Override
  public void setSessionNote(final String key, final String value) {
    this.sessionNotes.put(key, value);
  }
}
