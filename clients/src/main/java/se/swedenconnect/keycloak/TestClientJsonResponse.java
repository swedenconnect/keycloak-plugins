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

import net.minidev.json.JSONObject;

import java.util.Map;

/**
 * Json response from test client.
 *
 * @author Felix Hellman
 */
public class TestClientJsonResponse {
  private final JSONObject accessToken;
  private final JSONObject idToken;
  private final JSONObject userInfo;

  /**
   * Constructor.
   * @param accessToken
   * @param idToken
   * @param userInfo
   */
  public TestClientJsonResponse(final Map<String, Object> accessToken,
                                final Map<String, Object> idToken,
                                final Map<String, Object> userInfo) {

    this.accessToken = new JSONObject(accessToken);
    this.idToken = new JSONObject(idToken);
    this.userInfo = new JSONObject(userInfo);
  }

  /**
   * @return access token
   */
  public JSONObject getAccessToken() {
    return this.accessToken;
  }

  /**
   * @return id token
   */
  public JSONObject getIdToken() {
    return this.idToken;
  }

  /**
   * @return user info
   */
  public JSONObject getUserInfo() {
    return this.userInfo;
  }

  @Override
  public String toString() {
    return "TestClientJsonResponse{" + "accessToken=" + this.accessToken +
        ", idToken=" + this.idToken +
        ", userInfo=" + this.userInfo +
        '}';
  }
}
