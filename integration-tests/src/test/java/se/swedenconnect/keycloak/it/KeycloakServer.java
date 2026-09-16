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

import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.Ports;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.Assumptions;
import org.testcontainers.DockerClientFactory;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * One Keycloak container of the targeted version, with every plugin jar mounted, shared by all
 * integration test classes in this module.
 *
 * <p>Booting Keycloak takes tens of seconds, so the container is started once per JVM and stopped
 * by a shutdown hook (Testcontainers' Ryuk reaps it as well should the JVM die). Failsafe runs all
 * IT classes of this module in one forked JVM, so they all see the same instance.
 *
 * <p>The {@code transient-users} preview feature is enabled because the proxy set-ups this
 * repository targets run their brokers with {@code doNotStoreUsers=true}; several of the mappers
 * only populate user attributes in that mode.
 *
 * @author David Goldring
 */
final class KeycloakServer {

  /** Keycloak's own port inside the container; used for server-to-server calls between realms. */
  static final String INTERNAL_URL = "http://localhost:8080";

  /** Keycloak's fixed public hostname, once the container has started. */
  private static String hostname;

  private static KeycloakContainer container;

  private KeycloakServer() {
  }

  /**
   * Starts the shared container on first use.
   *
   * <p>Skips (rather than fails) the calling test when Docker is unavailable.
   *
   * @return the running container
   */
  static synchronized KeycloakContainer start() {
    Assumptions.assumeTrue(dockerAvailable(), "Docker is not available - skipping integration test");

    if (Objects.isNull(container)) {
      final String keycloakVersion = System.getProperty("keycloak.version");
      assertNotNull(keycloakVersion, "System property 'keycloak.version' must be set by the build");

      // A realm in this container brokers to another realm in the same container. The browser
      // reaches Keycloak through the mapped host port while the broker's back-channel calls hit
      // Keycloak's own port, and Keycloak validates the issuer of the tokens it sees on the
      // back-channel against the URL they were issued under. Pinning the hostname to the mapped
      // port makes both sides agree; that needs the port to be known before start-up.
      final int hostPort = freePort();
      hostname = "http://localhost:" + hostPort;
      final KeycloakContainer started = new KeycloakContainer("keycloak/keycloak:" + keycloakVersion)
          .withProviderLibsFrom(providerJars())
          .withFeaturesEnabled("transient-users")
          .withEnv("KC_HOSTNAME", hostname)
          .withEnv("KC_HOSTNAME_BACKCHANNEL_DYNAMIC", "true")
          .withStartupTimeout(Duration.ofMinutes(5));
      started.withCreateContainerCmdModifier(cmd -> bindHttpPort(cmd, hostPort));
      started.start();
      Runtime.getRuntime().addShutdownHook(new Thread(() -> stop(started), "stop-keycloak"));
      container = started;
    }
    return container;
  }

  /**
   * Replaces Testcontainers' random binding of Keycloak's HTTP port with a fixed one, keeping the
   * bindings of the other exposed ports (the management port) intact.
   */
  private static void bindHttpPort(final CreateContainerCmd cmd, final int hostPort) {
    final HostConfig hostConfig = Objects.requireNonNull(cmd.getHostConfig());
    final ExposedPort http = ExposedPort.tcp(8080);
    final Ports bindings = new Ports();
    Optional.ofNullable(hostConfig.getPortBindings())
        .map(Ports::getBindings)
        .ifPresent(existing -> existing.forEach((port, hosts) -> {
          if (!http.equals(port) && Objects.nonNull(hosts)) {
            for (final Ports.Binding host : hosts) {
              bindings.bind(port, host);
            }
          }
        }));
    bindings.bind(http, Ports.Binding.bindPort(hostPort));
    hostConfig.withPortBindings(bindings);
  }

  private static int freePort() {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
    catch (final IOException e) {
      throw new UncheckedIOException("Could not pick a free host port", e);
    }
  }

  /** Keeps the server log next to the failsafe reports, since the container is gone by then. */
  private static void stop(final KeycloakContainer started) {
    try {
      final Path log = Path.of(System.getProperty("keycloak.log", "target/keycloak-container.log"));
      Files.createDirectories(log.toAbsolutePath().getParent());
      Files.writeString(log, started.getLogs());
    }
    catch (final IOException | RuntimeException e) {
      System.err.println("Could not save the Keycloak container log: " + e);
    }
    started.stop();
  }

  /**
   * {@code DockerClientFactory.isDockerAvailable()} only swallows {@link IllegalStateException}, so
   * a daemon that is reachable but unusable still throws. Treat any failure as "no Docker".
   */
  private static boolean dockerAvailable() {
    try {
      return DockerClientFactory.instance().isDockerAvailable();
    }
    catch (final Throwable e) {
      return false;
    }
  }

  private static List<File> providerJars() {
    final Path providersDir = Path.of(System.getProperty("providers.dir", "target/providers"));
    try (Stream<Path> files = Files.list(providersDir)) {
      final List<File> jars = files
          .filter(path -> path.getFileName().toString().endsWith(".jar"))
          .map(Path::toFile)
          .sorted()
          .toList();
      assertFalse(jars.isEmpty(), "No provider jars staged in " + providersDir.toAbsolutePath());
      return jars;
    }
    catch (final IOException e) {
      throw new UncheckedIOException("Could not read staged provider jars from " + providersDir, e);
    }
  }
}
