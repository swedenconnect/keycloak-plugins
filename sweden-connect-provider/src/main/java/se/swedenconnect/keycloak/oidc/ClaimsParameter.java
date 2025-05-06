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

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Claims parameter from auth request, Implements {@link Predicate<AttributeClaim>} for checking if an attirbute
 * should be mapped.
 *
 * @author Felix Hellman
 */
public class ClaimsParameter implements Predicate<AttributeClaim> {
  private final Map<String, Object> claims;
  private final TokenType tokenType;

  /**
   * Type of token to evaluate for.
   */
  public enum TokenType {

    ID("id_token"),

    USERINFO("userinfo");

    private final String value;

    TokenType(final String value) {
      this.value = value;
    }
  }

  /**
   * Constructor.
   *
   * @param claims
   * @param tokenType
   */
  public ClaimsParameter(
      final Map<String, Object> claims,
      final TokenType tokenType
  ) {
    this.claims = claims;
    this.tokenType = tokenType;
  }

  @Override
  public boolean test(final AttributeClaim attributeClaim) {
    return Optional.ofNullable(this.claims.get(this.tokenType.value))
        .map(tokenClaim -> (Map<String, Object>) tokenClaim)
        .map(claims -> claims.containsKey(attributeClaim.getOidcClaimName()))
        .orElse(false);
  }

  /**
   * @return set of required parameters
   */
  public Set<String> getRequiredParameters() {
    return Optional.ofNullable(this.claims.get(this.tokenType.value))
        .map(tokenClaim -> (Map<String, Object>) tokenClaim)
        .map(claims -> claims.entrySet().stream()
            .filter(e -> {
              if (e.getValue() instanceof Map<?, ?> param) {
                return param.containsKey("essential") && (Boolean) param.get("essential");
              }
              return false;
            })
            .map(Map.Entry::getKey)
            .collect(Collectors.toSet()))
        .orElse(Set.of());
  }
}
