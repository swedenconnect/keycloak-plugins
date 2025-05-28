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
package se.swedenconnect.keycloak.oidf;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.trust.marks.TrustMarkEntry;

import java.util.List;
import java.util.Map;

public class ResolvedEntity {

  private final SignedJWT jwt;

  public ResolvedEntity(final SignedJWT jwt) {
    this.jwt = jwt;
  }

  public String getSubject() {
    return this.jwt.getJWTClaimsSet().getSubject();
  }

  public Map<String, Object> getMetadata() {
    return this.jwt.getJWTClaimsSet().getJSONObjectClaim("metadata");
  }

  public List<TrustMarkEntry> trustMarks() {
    return this.jwt.getJWTClaimsSet().getListClaim("trust_marks");
  }

  public SignedJWT getJwt() {
    return jwt;
  }
}
