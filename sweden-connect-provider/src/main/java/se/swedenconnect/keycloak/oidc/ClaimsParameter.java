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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
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

  /**
   * Merges this claims parameter with other
   *
   * @param other to merge with
   * @return this after resulting merge
   */
  public ClaimsParameter merge(final ClaimsParameter other) {
    if (Objects.nonNull(other)) {
      final Map<String, Object> idToken = (Map<String, Object>) other.claims.get("id_token");
      if (Objects.nonNull(idToken)) {
        this.claims.put("id_token", new HashMap<String, Object>());
        idToken.keySet()
            .stream()
            .filter(key -> Objects.nonNull(idToken.get(key)))
            .forEach(key -> {
          ((Map<String, Object>) this.claims.get("id_token")).put(key, idToken.get(key));
        });
      }
      final Map<String, Object> userinfo = (Map<String, Object>) other.claims.get("userinfo");
      this.claims.put("userinfo", new HashMap<String, Object>());
      if (Objects.nonNull(userinfo)) {
        userinfo.keySet()
            .stream()
            .filter(key -> Objects.nonNull(userinfo.get(key)))
            .forEach(key -> {
          ((Map<String, Object>) this.claims.get("userinfo")).put(key, userinfo.get(key));
        });
      }
    }
    return this;
  }

  /**
   * @param scope to create from
   * @return new instance of scope is supported otherwise null
   */
  public static ClaimsParameter fromScope(final String scope) {
    return switch (scope) {
      case "https://id.oidc.se/scope/naturalPersonInfo" -> new ClaimsParameter(Map.of("userinfo", Map.of(
          "family_name", Map.of(),
          "given_name", Map.of(),
          "middle_name", Map.of(),
          "name", Map.of(),
          "birthdate", Map.of()
      )), null);
      case "https://id.oidc.se/scope/naturalPersonOrgId" -> new ClaimsParameter(
          Map.of("userinfo", Map.of(
                  "name", Map.of(),
                  "https://id.oidc.se/claim/orgName", Map.of(),
                  "https://id.oidc.se/claim/orgNumber", Map.of(),
                  "https://id.oidc.se/claim/orgAffiliation", Map.of("essential", true)
              ),
              "id_token", Map.of(
                  "https://id.oidc.se/claim/orgAffiliation", Map.of("essential", true)
              )), null);
      case "https://id.oidc.se/scope/naturalPersonNumber" -> new ClaimsParameter(
          Map.of("userinfo", Map.of(
                  "https://id.oidc.se/claim/personalIdentityNumber", Map.of("essential", true),
                  "https://id.oidc.se/claim/coordinationNumber", Map.of("essential", true)
              ),
              "id_token", Map.of(
                  "https://id.oidc.se/claim/personalIdentityNumber", Map.of("essential", true),
                  "https://id.oidc.se/claim/coordinationNumber", Map.of("essential", true)
              )), null);
      case "https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity" -> new ClaimsParameter(
          Map.of("userinfo", Map.of(
                  "https://id.swedenconnect.se/claim/prid", Map.of("essential", true),
                  "https://id.swedenconnect.se/claim/pridPersistence", Map.of("essential", true),
                  "https://id.swedenconnect.se/claim/eidasPersonIdentifier", Map.of("essential", true)
              ),
              "id_token", Map.of(
                  "https://id.swedenconnect.se/claim/prid", Map.of("essential", true),
                  "https://id.swedenconnect.se/claim/pridPersistence", Map.of("essential", true)
              )), null);
      case "https://id.swedenconnect.se/scope/eidasSwedishIdentity" -> new ClaimsParameter(
          Map.of("userinfo", Map.of(
                  "https://id.swedenconnect.se/claim/mappedPersonalIdentityNumber", Map.of()
              )), null);
      default -> null;
    };
  }

  @Override
  public String toString() {
    return "ClaimsParameter{" + "claims=" + this.claims +
        ", tokenType=" + this.tokenType +
        '}';
  }
}
