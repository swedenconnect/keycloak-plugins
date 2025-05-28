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
import org.keycloak.crypto.KeyUse;
import org.keycloak.keys.Attributes;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Utility class for loading shared component models.
 *
 * @author Felix Hellman.
 */
public class SharedKeyModelLoader {
  /**
   * Load Shared Model if allowed.
   * @param session for finding realms
   * @param model to set key use
   * @return model if present
   */
  public static Optional<ComponentModel> loadModel(final KeycloakSession session, final ComponentModel model) {
    final Set<RealmProvider> realmProviders = session.getAllProviders(RealmProvider.class);

    final String realmName = Optional.ofNullable(model.getConfig().get("sharedRealmName")).orElse(List.of())
        .stream()
        .findFirst()
        .orElse("master");

    final String keyName = Optional.ofNullable(model.getConfig().get("sharedKeyName"))
        .orElse(List.of())
        .stream().findFirst()
        .orElse("shareable-key");

    final RealmProvider realmProvider = realmProviders.stream().findFirst()
        .get();

    final Optional<RealmModel> sharedRealm = realmProvider.getRealmsStream()
        .filter(r -> realmName.equals(r.getName()))
        .findFirst();

    return sharedRealm.get().getComponentsStream()
        .filter(c -> keyName.equals(c.getName()))
        .filter(c -> {
          final List<String> realms = c.getConfig().get("shareableKeyAllowedRealms");
          if (realms == null) {
            return false;
          }
          return !realms.isEmpty();
        })
        .filter(c -> {
          final String[] split = c.getConfig().get("shareableKeyAllowedRealms")
              .getFirst()
              .split(",");

          return Arrays.stream(split)
              .map(String::trim)
              .anyMatch(
                  realm -> session.getContext()
                      .getRealm().getName()
                      .equalsIgnoreCase(realm)
              );
        })
        .findFirst();
  }
}
