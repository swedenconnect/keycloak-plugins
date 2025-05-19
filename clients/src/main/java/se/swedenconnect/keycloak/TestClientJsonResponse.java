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

public class TestClientJsonResponse {
  private final JSONObject accessToken;
  private final JSONObject idToken;
  private final JSONObject userInfo;

  public TestClientJsonResponse(final Map<String, Object> accessToken,
                                final Map<String, Object> idToken,
                                final Map<String, Object> userInfo) {

    this.accessToken = new JSONObject(accessToken);
    this.idToken = new JSONObject(idToken);
    this.userInfo = new JSONObject(userInfo);
  }

  public JSONObject getAccessToken() {
    return this.accessToken;
  }

  public JSONObject getIdToken() {
    return this.idToken;
  }

  public JSONObject getUserInfo() {
    return this.userInfo;
  }

  @Override
  public String toString() {
    final StringBuffer sb = new StringBuffer("TestClientJsonResponse{");
    sb.append("accessToken=").append(accessToken);
    sb.append(", idToken=").append(idToken);
    sb.append(", userInfo=").append(userInfo);
    sb.append('}');
    return sb.toString();
  }
}
