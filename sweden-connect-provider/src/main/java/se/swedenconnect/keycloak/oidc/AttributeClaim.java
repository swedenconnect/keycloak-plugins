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

/**
 * Data class for holding how an attribute maps from saml to oidc.
 *
 * @author Felix Hellman
 */
public class AttributeClaim {
  private final String samlAttributeName;
  private final String oidcClaimName;

  /**
   * Constructor.
   * @param samlAttributeName
   * @param oidcClaimName
   */
  public AttributeClaim(
      final String samlAttributeName,
      final String oidcClaimName) {

    this.samlAttributeName = samlAttributeName;
    this.oidcClaimName = oidcClaimName;
  }

  /**
   * @return saml attribute name
   */
  public String getSamlAttributeName() {
    return this.samlAttributeName;
  }

  /**
   * @return oidc claim name
   */
  public String getOidcClaimName() {
    return this.oidcClaimName;
  }

  /**
   * Creates a builder.
   * @param samlAttributeName
   * @param oidcClaimName
   * @return new builder instance
   */
  public static Builder builder(
      final String samlAttributeName,
      final String oidcClaimName) {

    return new Builder(samlAttributeName, oidcClaimName);
  }

  /**
   * Builder class for AttributeClaim.
   *
   * @author Felix Hellman
   */
  public static class Builder {
    private final String samlAttributeName;
    private final String oidcClaimName;

    /**
     * Constructor.
     * @param samlAttributeName
     * @param oidcClaimName
     */
    public Builder(final String samlAttributeName, final String oidcClaimName) {
      this.samlAttributeName = samlAttributeName;
      this.oidcClaimName = oidcClaimName;
    }

    /**
     * @return new AttributeClaim instance
     */
    public AttributeClaim build() {
      return new AttributeClaim(
          this.samlAttributeName,
          this.oidcClaimName
      );
    }
  }
}
