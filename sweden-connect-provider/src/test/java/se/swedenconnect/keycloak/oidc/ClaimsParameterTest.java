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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

class ClaimsParameterTest {

  @Test
  void combineTest() {
    final ClaimsParameter p1 = new ClaimsParameter(Map.of(), ClaimsParameter.TokenType.ID);
    final ClaimsParameter p2 = ClaimsParameter
        .fromScope("https://id.oidc.se/scope/naturalPersonNumber");
    final ClaimsParameter p3 = ClaimsParameter
        .fromScope("https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity");

    final ClaimsParameter merged = p1
        .combine(p2)
        .combine(p3);

    Assertions.assertTrue(merged.getRequiredParameters().contains("https://id.swedenconnect.se/claim/prid"));
    Assertions.assertTrue(merged.getRequiredParameters().contains("https://id.oidc.se/claim/personalIdentityNumber"));

    Assertions.assertTrue(p1.getRequiredParameters().contains("https://id.swedenconnect.se/claim/prid"));
    Assertions.assertTrue(p1.getRequiredParameters().contains("https://id.oidc.se/claim/personalIdentityNumber"));

    Assertions.assertSame(p1, merged);
  }

  @Test
  void splitAndCombineFromScopes() {
    final HashMap<String, Object> stringObjectHashMap = new HashMap<>();
    stringObjectHashMap.put("a", null);
    final ClaimsParameter claims = new ClaimsParameter(Map.of("id_token", stringObjectHashMap), ClaimsParameter.TokenType.ID);
    Arrays.stream("openid https://id.oidc.se/scope/naturalPersonNumber https://id.swedenconnect.se/claim/prid".split(
        " "))
        .forEach(scope -> {
          if (Objects.nonNull(scope)) {
            final ClaimsParameter other = ClaimsParameter.fromScope(scope);
            if (Objects.nonNull(other)) {
              claims.combine(other);
            }
          }
        });
  }
}