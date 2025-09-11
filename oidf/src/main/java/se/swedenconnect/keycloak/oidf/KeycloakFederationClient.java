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
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.EntityConfigurationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FetchRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.ResolveRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.SubordinateListingRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkListingRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkRequest;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class KeycloakFederationClient implements FederationClient {
  
  private final CloseableHttpClient client;

  public KeycloakFederationClient(final KeycloakSession session) {
    this.client = session.getProvider(HttpClientProvider.class).getHttpClient();
  }

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
    try {
      final CloseableHttpResponse response = this.client.execute(
          new HttpHost((String) federationRequest
              .federationEntityMetadata()
              .get("federation_trust_mark_endpoint")),
          new HttpGet());

      final String trustMark = new String(
          response.getEntity()
              .getContent()
              .readAllBytes(), StandardCharsets.UTF_8
      );

      return SignedJWT.parse(trustMark);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
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
