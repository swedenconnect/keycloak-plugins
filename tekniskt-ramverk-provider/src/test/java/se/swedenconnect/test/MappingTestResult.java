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

import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.List;
import java.util.Map;

public class MappingTestResult {
  private final Map<String, String> samlInput;
  private final IDToken idToken;
  private final AccessToken accessToken;
  private final AccessToken userInfo;

  public MappingTestResult(final Map<String, String> samlInput,
                           final IDToken idToken,
                           final AccessToken accessToken,
                           final AccessToken userInfo) {

    this.samlInput = samlInput;
    this.idToken = idToken;
    this.accessToken = accessToken;
    this.userInfo = userInfo;
  }

  public Map<String, String> getSamlInput() {
    return samlInput;
  }

  public IDToken getIdToken() {
    return idToken;
  }

  public AccessToken getAccessToken() {
    return accessToken;
  }

  public AccessToken getUserInfo() {
    return userInfo;
  }

  public void printReport() {
    System.out.println("==== SAML INPUT ====");
    System.out.println(this.getSamlInput());
    System.out.println("==== ACCESS TOKEN ====");
    System.out.println(this.getAccessToken().getOtherClaims());
    System.out.println("==== ID TOKEN ====");
    System.out.println(this.getIdToken().getOtherClaims());
    System.out.println("==== USERINFO ====");
    System.out.println(this.getUserInfo().getOtherClaims());
  }
}
