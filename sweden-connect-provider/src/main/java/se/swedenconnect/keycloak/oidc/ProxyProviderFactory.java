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
package se.swedenconnect.keycloak.oidc;

import org.keycloak.broker.oidc.KeycloakOIDCIdentityProvider;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * ProxyProviderFactory for creating a proxy provider.
 *
 * @author Felix Hellman
 */
public class ProxyProviderFactory extends KeycloakOIDCIdentityProviderFactory {
  @Override
  public String getName() {
    return "Proxy Provider";
  }

  @Override
  public KeycloakOIDCIdentityProvider create(
      final KeycloakSession keycloakSession,
      final IdentityProviderModel identityProviderModel) {

    return new ProxyProvider(
        keycloakSession,
        new OIDCIdentityProviderConfig(identityProviderModel)
    );
  }
}
