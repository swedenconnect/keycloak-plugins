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
package se.swedenconnect.keycloak.broker;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Unit tests for {@link IdpHintOidcIdentityProviderFactory}.
 *
 * @author David Goldring
 */
@ExtendWith(MockitoExtension.class)
class IdpHintOidcIdentityProviderFactoryTest {

  @Mock
  private KeycloakSession session;

  private final IdpHintOidcIdentityProviderFactory factory = new IdpHintOidcIdentityProviderFactory();

  @Test
  void getId_returnsProviderId() {
    assertEquals(IdpHintOidcIdentityProviderFactory.PROVIDER_ID, this.factory.getId());
  }

  @Test
  void getName_isNonBlank() {
    assertNotNull(this.factory.getName());
    org.junit.jupiter.api.Assertions.assertFalse(this.factory.getName().isBlank());
  }

  @Test
  void getHelpText_isNonBlank() {
    assertNotNull(this.factory.getHelpText());
    org.junit.jupiter.api.Assertions.assertFalse(this.factory.getHelpText().isBlank());
  }

  @Test
  void create_returnsIdpHintOidcIdentityProvider() {
    final IdentityProviderModel model = new IdentityProviderModel();
    model.setAlias("test-idp");

    final IdpHintOidcIdentityProvider provider = this.factory.create(this.session, model);

    assertInstanceOf(IdpHintOidcIdentityProvider.class, provider);
  }
}
