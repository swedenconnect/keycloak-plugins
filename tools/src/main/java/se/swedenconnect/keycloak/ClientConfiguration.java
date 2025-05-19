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
package se.swedenconnect.keycloak;

import java.util.Map;

/**
 * Configuration class for client.
 *
 * @author Felix Hellman
 */
public class ClientConfiguration {
  private final String clientId;
  private final String clientSecret;
  private final String authEndpoint;
  private final String tokenEndpoint;
  private final String userInfoEndpoint;

  /**
   * Constructor.
   * @param config (from config.yml)
   */
  public ClientConfiguration(final Map<String, String> config) {
    this.clientId = config.get("client-id");
    this.clientSecret = config.get("client-secret");
    this.authEndpoint = config.get("auth-endpoint");
    this.tokenEndpoint = config.get("token-endpoint");
    this.userInfoEndpoint = config.get("userinfo-endpoint");
  }

  /**
   * @return client id
   */
  public String getClientId() {
    return this.clientId;
  }

  /**
   * @return client secret
   */
  public String getClientSecret() {
    return this.clientSecret;
  }

  /**
   * @return auth endpoint
   */
  public String getAuthEndpoint() {
    return this.authEndpoint;
  }

  /**
   * @return token endpoint
   */
  public String getTokenEndpoint() {
    return this.tokenEndpoint;
  }

  /**
   * @return userInfo endpoint
   */
  public String getUserInfoEndpoint() {
    return this.userInfoEndpoint;
  }
}
