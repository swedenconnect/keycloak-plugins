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
import se.swedenconnect.oidf.common.entity.entity.integration.federation.ResolveRequest;
import se.swedenconnect.oidf.common.entity.exception.FederationException;
import se.swedenconnect.oidf.common.entity.tree.Tree;
import se.swedenconnect.oidf.resolver.DiscoveryRequest;
import se.swedenconnect.oidf.resolver.DiscoveryResponse;
import se.swedenconnect.oidf.resolver.Resolver;
import se.swedenconnect.oidf.resolver.tree.EntityStatementTreeLoader;

import java.text.ParseException;
import java.util.List;

public class KeycloakResolver {
  private final Resolver resolver;
  private final EntityStatementTreeLoader loader;
  private final Tree<EntityStatement> entityStatementTree;
  private final String trustAnchor;

  public DiscoveryResponse discovery() {
    return resolver.discovery(new DiscoveryRequest(this.trustAnchor, null, null));
  }

  public SignedJWT resolve(final String subject) throws FederationException {
    try {
      return SignedJWT.parse(resolver.resolve(new ResolveRequest(subject, null, null)));
    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
  }

  public List<ResolvedEntity> discoveryAll() {
    return this.discovery().supportedEntities()
        .stream().map(entity -> {
          try {
            return this.resolve(entity);
          } catch (FederationException e) {
            throw new RuntimeException(e);
          }
        })
        .map(ResolvedEntity::new)
        .toList();
  }

  public void load() {
    this.loader.resolveTree(trustAnchor, entityStatementTree);
  }
}
