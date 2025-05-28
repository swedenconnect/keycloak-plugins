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
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.EntityConfigurationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FetchRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.ResolveRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.SubordinateListingRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkListingRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkRequest;

import java.util.List;

public class OIDFFederationClient implements FederationClient {
  @Override
  public EntityStatement entityConfiguration(final FederationRequest<EntityConfigurationRequest> federationRequest) {
    return null;
  }

  @Override
  public EntityStatement fetch(final FederationRequest<FetchRequest> federationRequest) {
    return null;
  }

  @Override
  public List<String> subordinateListing(final FederationRequest<SubordinateListingRequest> federationRequest) {
    return List.of();
  }

  @Override
  public SignedJWT trustMark(final FederationRequest<TrustMarkRequest> federationRequest) {
    return null;
  }

  @Override
  public SignedJWT resolve(final FederationRequest<ResolveRequest> federationRequest) {
    return null;
  }

  @Override
  public List<String> trustMarkedListing(final FederationRequest<TrustMarkListingRequest> federationRequest) {
    return List.of();
  }
}
