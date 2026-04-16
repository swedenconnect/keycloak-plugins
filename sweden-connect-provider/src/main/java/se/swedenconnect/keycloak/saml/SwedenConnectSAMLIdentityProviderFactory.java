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
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.saml.validators.DestinationValidator;

/**
 * Factory for {@link SwedenConnectSAMLIdentityProvider}.
 *
 * @author Felix Hellman
 */
public class SwedenConnectSAMLIdentityProviderFactory extends SAMLIdentityProviderFactory {

  private DestinationValidator destinationValidator;

  @Override
  public void init(final Config.Scope config) {
    super.init(config);
    this.destinationValidator = DestinationValidator.forProtocolMap(config.getArray("knownProtocols"));
  }

  @Override
  public SwedenConnectSAMLIdentityProvider create(
      final KeycloakSession session,
      final IdentityProviderModel model) {
    return new SwedenConnectSAMLIdentityProvider(
        session,
        new SAMLIdentityProviderConfig(model),
        this.destinationValidator
    );
  }
}
