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
 *
 */
package se.swedenconnect.keycloak.it;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.info.ServerInfoRepresentation;
import org.keycloak.representations.info.SpiInfoRepresentation;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Boots a real Keycloak of the targeted version with every plugin jar mounted and asserts that all
 * provider IDs register.
 *
 * <p>This guards against breakage that compiles clean but shows up only at provider load time:
 * a class named in a {@code META-INF/services} file that no longer exists, a class that is on the
 * compile classpath but missing from the shaded jar or the server runtime, a factory whose
 * {@code init()} throws, or one of our factories losing the ID race against a Keycloak built-in.
 *
 * <p>Note what this does <em>not</em> cover: a Keycloak release adding an abstract method to a
 * factory interface is caught by {@code mvn compile}, not here. The JVM only raises
 * {@link AbstractMethodError} when such a method is invoked, so a jar built against the older
 * interface still loads and still registers - verified by building {@code pkcs11} against 26.4.0
 * and running it on 26.7.3, where all IDs below were still present.
 *
 * @author David Goldring
 */
class ProviderRegistrationIT {

  /**
   * Every {@code getId()} return value of the modules the default reactor builds. Regenerate by
   * grepping for {@code String getId()} across the {@code src/main/java} tree of every module.
   *
   * <p>The parked modules are deliberately absent: {@code idp-hint-oidc-provider}
   * ({@code oidc-idp-hint}) and {@code saml-session-note-mapper}
   * ({@code saml-session-note-mapper}, {@code transient-session-note-claim-mapper},
   * {@code oidc-claim-to-broker-id-mapper}) are built only under {@code -Pparked} and are not
   * staged into the container, so the server never registers them here.
   */
  private static final Set<String> EXPECTED_PROVIDER_IDS = Set.of(
      "IDP-FILTER",
      "Idp-Selector",
      "oidf",
      "pkcs-11-hsm-key",
      "PKCS11-Signature-Provider",
      "Sweden-Connect",
      "Sweden-Connect-OP",
      "Sweden-Connect-SAML-Mapper",
      "rfc8707-resource-indicator",
      "resource-mapper",
      "resource-authenticator",
      "shareable-rsa-key",
      "shareable-ec-key",
      "shareable-rsa-enc-key",
      "shared-rsa-key",
      "shared-ec-key",
      "shared-rsa-enc-key"
  );

  /** Substrings that mark a log line as being about a failed provider load rather than noise. */
  private static final List<String> LOAD_FAILURE_MARKERS = List.of(
      "NoSuchMethodError",
      "AbstractMethodError",
      "NoClassDefFoundError",
      "ClassNotFoundException",
      "InstantiationException",
      "ServiceConfigurationError",
      "IncompatibleClassChangeError",
      "Failed to load provider",
      "Failed to create provider",
      "Error loading provider",
      "Failed to initialize provider"
  );

  private static KeycloakContainer keycloakContainer;

  @BeforeAll
  static void startKeycloak() {
    keycloakContainer = KeycloakServer.start();
  }

  /**
   * Assertion A: every provider ID in the repository is registered by the running server.
   *
   * <p>The SPI names the providers live under ({@code keys}, {@code signature},
   * {@code realm-restapi-extension}, ...) are an internal Keycloak detail, so the provider maps of
   * all SPIs are flattened into one set rather than asserted per SPI.
   */
  @Test
  void allProviderIdsAreRegistered() {
    final Map<String, SpiInfoRepresentation> providersBySpi = serverInfo().getProviders();
    assertNotNull(providersBySpi, "Server info returned no provider information");

    final Set<String> registered = providersBySpi.values().stream()
        .map(SpiInfoRepresentation::getProviders)
        .filter(Objects::nonNull)
        .flatMap(providers -> providers.keySet().stream())
        .collect(Collectors.toSet());

    final Set<String> missing = EXPECTED_PROVIDER_IDS.stream()
        .filter(id -> !registered.contains(id))
        .collect(Collectors.toCollection(TreeSet::new));

    assertTrue(missing.isEmpty(), "Provider IDs missing from the running Keycloak: " + missing);
  }

  /**
   * Assertion B: the broker factory overrides took effect.
   *
   * <p>{@code ProxyProviderFactory} and {@code SwedenConnectSAMLIdentityProviderFactory} do not
   * override {@code getId()} - they inherit {@code keycloak-oidc} and {@code saml} respectively and
   * replace Keycloak's built-ins. So the presence of those IDs proves nothing. {@code
   * ProxyProviderFactory} does override {@code getName()}, which gives positive proof that our
   * factory won the ServiceLoader race.
   *
   * <p>{@code SwedenConnectSAMLIdentityProviderFactory} overrides neither {@code getId()} nor
   * {@code getName()}, so it is indistinguishable from the built-in {@code saml} provider over the
   * admin API; it is deliberately not asserted here rather than faking a check.
   */
  @Test
  void proxyProviderReplacesTheBuiltInOidcBroker() {
    final List<Map<String, String>> identityProviders = serverInfo().getIdentityProviders();
    assertNotNull(identityProviders, "Server info returned no identity provider information");

    final Map<String, String> keycloakOidc = identityProviders.stream()
        .filter(idp -> "keycloak-oidc".equals(idp.get("id")))
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "No 'keycloak-oidc' identity provider registered. Registered: " + identityProviders));

    assertEquals("Proxy Provider", keycloakOidc.get("name"),
        "The 'keycloak-oidc' broker is not backed by ProxyProviderFactory");
  }

  /**
   * Assertion C: the providers loaded cleanly.
   *
   * <p>Catches breakage that degrades a provider rather than deregistering it, which
   * {@link #allProviderIdsAreRegistered()} would not see.
   */
  @Test
  void noProviderLoadErrorsInTheServerLog() {
    final List<String> errors = keycloakContainer.getLogs().lines()
        .filter(line -> line.contains("ERROR"))
        .filter(line -> LOAD_FAILURE_MARKERS.stream().anyMatch(line::contains))
        .toList();

    assertTrue(errors.isEmpty(), "Provider load errors in the Keycloak log:\n" + String.join("\n", errors));
  }

  private static ServerInfoRepresentation serverInfo() {
    try (Keycloak admin = keycloakContainer.getKeycloakAdminClient()) {
      return admin.serverInfo().getInfo();
    }
  }
}
