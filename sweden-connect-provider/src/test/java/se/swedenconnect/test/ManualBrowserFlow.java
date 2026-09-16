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

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.utility.MountableFile;
import se.swedenconnect.keycloak.TestClientJsonResponse;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Manual debugging harness that drives a full brokered login against a containerized Keycloak.
 *
 * <p>This is <em>not</em> an automated test: {@link KeycloakIntegrationTestCase} runs the client
 * non-headless, so it opens a real desktop browser and blocks until a human completes the flow.
 * Run it from the IDE when debugging the broker path. The class name deliberately carries neither
 * an {@code IT} nor a {@code Test} suffix so that neither surefire nor failsafe can pick it up.
 *
 * <p>Requires {@code mvn package} to have produced the provider jar in {@code target/} first, and
 * requires {@code -Dkeycloak.version=...} on the command line or in the IDE run configuration.
 * Nothing here is version-pinned, so this harness cannot silently drift onto a stale Keycloak.
 */
public class ManualBrowserFlow {

  private static final Logger LOG = Logger.getLogger("DOCKER");

  private KeycloakContainer keycloakContainer;

  @BeforeEach
  void startKeycloak() {
    final String keycloakVersion = Objects.requireNonNull(System.getProperty("keycloak.version"),
        "Set -Dkeycloak.version=<tag> (the version this branch targets) before running this harness");

    this.keycloakContainer = new KeycloakContainer("keycloak/keycloak:" + keycloakVersion);
    this.keycloakContainer.setLogConsumers(List.of(c -> LOG.info(c.getUtf8String())));
    this.keycloakContainer.withAccessToHost(true)
        .withCopyFileToContainer(MountableFile.forHostPath(providerJar()), "/opt/keycloak/providers/")
        .start();
  }

  /**
   * Locates the built provider jar rather than naming a version, so a release bump cannot leave
   * this harness mounting a jar that no longer exists.
   *
   * @return the shaded provider jar in {@code target/}
   */
  private static Path providerJar() {
    final Path target = Path.of("target");
    try (Stream<Path> files = Files.list(target)) {
      return files
          .filter(path -> path.getFileName().toString().endsWith("-jar-with-dependencies.jar"))
          .findFirst()
          .orElseThrow(() -> new IllegalStateException(
              "No shaded provider jar in " + target.toAbsolutePath() + " - run `mvn package` first"));
    }
    catch (final IOException e) {
      throw new UncheckedIOException("Could not list " + target.toAbsolutePath(), e);
    }
  }

  @AfterEach
  void stopKeycloak() {
    if (Objects.nonNull(this.keycloakContainer)) {
      this.keycloakContainer.stop();
    }
  }

  @Test
  void test() throws Exception {
    final KeycloakIntegrationTestCase testCase = new KeycloakIntegrationTestCase(a -> {
    }, this.keycloakContainer);

    final TestClientJsonResponse execute = testCase.execute();

    Assertions.assertEquals("https://testclient.se", execute.getAccessToken().get("azp"));
  }
}
