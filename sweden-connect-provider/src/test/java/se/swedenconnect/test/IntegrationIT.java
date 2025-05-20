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
import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.testcontainers.utility.CommandLine;
import org.testcontainers.utility.MountableFile;
import se.swedenconnect.keycloak.TestClientJsonResponse;

import java.util.List;


public class IntegrationIT {

  private static final KeycloakContainer keycloakContainer = new KeycloakContainer("keycloak/keycloak:26.2.2");

  static {
    final Logger log = Logger.getLogger("DOCKER");
    keycloakContainer.setLogConsumers(List.of(c -> log.info(c.getUtf8String())));
    keycloakContainer.withAccessToHost(true)
        .withCopyFileToContainer(
            MountableFile.forHostPath("target/sweden-connect-provider-0.2.jar"),
        "/opt/keycloak/providers/")
        .start();
  }

  @Test
  void test() throws Exception {
    final KeycloakIntegrationTestCase testCase = new KeycloakIntegrationTestCase(a -> {
    }, keycloakContainer);

    final TestClientJsonResponse execute = testCase.execute();

    Assertions.assertEquals("https://testclient.se", execute.getAccessToken().get("azp"));
  }
}
