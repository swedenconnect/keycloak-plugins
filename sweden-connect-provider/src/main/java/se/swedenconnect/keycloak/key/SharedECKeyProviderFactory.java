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
package se.swedenconnect.keycloak.key;

import org.keycloak.component.ComponentModel;
import org.keycloak.keys.GeneratedEcdsaKeyProviderFactory;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Key Provider for loading a shared ec key.
 *
 * @author Felix Hellman
 */
public class SharedECKeyProviderFactory implements KeyProviderFactory {

  private final KeyProviderFactory delegate = new GeneratedEcdsaKeyProviderFactory();

  @Override
  public KeyProvider create(final KeycloakSession session, final ComponentModel model) {
    final Optional<ComponentModel> sharedKeyModel = SharedKeyModelLoader.loadModel(session, model);
    return this.delegate.create(session, sharedKeyModel.orElseGet(() -> model));
  }

  @Override
  public String getHelpText() {
    return "Load a Shared Key";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    final ArrayList<ProviderConfigProperty> properties = new ArrayList<>();

    properties.add(
        new ProviderConfigProperty(
            "sharedRealmName",
            "Realm Name",
            "Name of the realm that contains the key",
            ProviderConfigProperty.STRING_TYPE,
            "master"
        )
    );
    properties.add(
        new ProviderConfigProperty(
            "sharedKeyName",
            "Shared Key Name",
            "Name of the shared Key",
            ProviderConfigProperty.STRING_TYPE,
            "shareable-key"
        )
    );

    return properties;
  }

  @Override
  public String getId() {
    return "shared-ec-key";
  }
}
