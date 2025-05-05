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
  private final Boolean idToken;
  private final Boolean accessToken;
  private final Boolean userInfo;

  /**
   * Constructor.
   * @param samlAttributeName
   * @param oidcClaimName
   * @param idToken
   * @param accessToken
   * @param userInfo
   */
  public AttributeClaim(
      final String samlAttributeName,
      final String oidcClaimName,
      final Boolean idToken,
      final Boolean accessToken,
      final Boolean userInfo) {

    this.samlAttributeName = samlAttributeName;
    this.oidcClaimName = oidcClaimName;
    this.idToken = idToken;
    this.accessToken = accessToken;
    this.userInfo = userInfo;
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
   * @return id token
   */
  public Boolean getIdToken() {
    return this.idToken;
  }

  /**
   * @return access token
   */
  public Boolean getAccessToken() {
    return this.accessToken;
  }

  /**
   * @return user info
   */
  public Boolean getUserInfo() {
    return this.userInfo;
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
    private Boolean idToken = false;
    private Boolean accessToken = false;
    private Boolean userInfo = false;

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
     * @param accessToken true if this claim should be present in access token
     * @return this
     */
    public Builder accessToken(final Boolean accessToken) {
      this.accessToken = accessToken;
      return this;
    }

    /**
     * @param userInfo true if this claim should be present in user info
     * @return this
     */
    public Builder userInfo(final Boolean userInfo) {
      this.userInfo = userInfo;
      return this;
    }

    /**
     * @param idToken true if this claim should be present in id token
     * @return this
     */
    public Builder idToken(final Boolean idToken) {
      this.idToken = idToken;
      return this;
    }

    /**
     * @return new AttributeClaim instance
     */
    public AttributeClaim build() {
      return new AttributeClaim(
          this.samlAttributeName,
          this.oidcClaimName,
          this.idToken,
          this.accessToken,
          this.userInfo
      );
    }
  }
}
