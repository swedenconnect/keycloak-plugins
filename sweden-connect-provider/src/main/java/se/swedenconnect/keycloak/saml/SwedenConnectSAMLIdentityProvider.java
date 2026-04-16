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

import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.validators.DestinationValidator;

/**
 * SAML identity provider that forwards cancel responses back to the OAuth2 client's redirect_uri.
 *
 * @author Felix Hellman
 */
public class SwedenConnectSAMLIdentityProvider extends SAMLIdentityProvider {

  private final DestinationValidator destinationValidator;

  /**
   * Constructor.
   *
   * @param session session
   * @param config config
   * @param destinationValidator destinationValidator
   */
  public SwedenConnectSAMLIdentityProvider(
      final KeycloakSession session,
      final SAMLIdentityProviderConfig config,
      final DestinationValidator destinationValidator) {
    super(session, config, destinationValidator);
    this.destinationValidator = destinationValidator;
  }

  @Override
  public Object callback(
      final RealmModel realm,
      final IdentityProvider.AuthenticationCallback callback,
      final EventBuilder event) {
    return new SwedenConnectSAMLEndpoint(session, this, getConfig(), callback, this.destinationValidator);
  }
}
