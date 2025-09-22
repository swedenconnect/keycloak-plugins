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

import org.keycloak.Config;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.saml.validators.DestinationValidator;

import java.util.Map;

public class VirtualSamlIdentityProviderFactory implements IdentityProviderFactory<VirtualSamlIdentityProvider> {
  @Override
  public String getName() {
    return "Virtual Saml Identity Provider";
  }

  @Override
  public VirtualSamlIdentityProvider create(final KeycloakSession keycloakSession, final IdentityProviderModel identityProviderModel) {
    return new VirtualSamlIdentityProvider(
        keycloakSession,
        new SAMLIdentityProviderConfig(),
        DestinationValidator.forProtocolMap(new String[]{"http=80", "https=443"})
    );
  }

  @Override
  public Map<String, String> parseConfig(final KeycloakSession keycloakSession, final String s) {
    return Map.of();
  }

  @Override
  public IdentityProviderModel createConfig() {
    return null;
  }

  @Override
  public VirtualSamlIdentityProvider create(final KeycloakSession session) {
    return null;
  }

  @Override
  public void init(final Config.Scope config) {

  }

  @Override
  public void postInit(final KeycloakSessionFactory factory) {

  }

  @Override
  public void close() {

  }

  @Override
  public String getId() {
    return "Virtual-Saml-Identity-Provider";
  }
}
