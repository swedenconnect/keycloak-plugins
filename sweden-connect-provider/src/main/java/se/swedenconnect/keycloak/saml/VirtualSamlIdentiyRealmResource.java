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
package se.swedenconnect.keycloak.saml;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import java.net.URLDecoder;
import java.nio.charset.Charset;

public class VirtualSamlIdentiyRealmResource implements RealmResourceProvider {

  private final KeycloakSession session;

  public VirtualSamlIdentiyRealmResource(final KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Override
  public void close() {

  }

  @GET
  @Path("/metadata/saml")
  public Response getMetadata(@QueryParam("entity") final String entity) {
    session.getContext().getRealm().getClientsStream()
        .filter(c -> {
          final String clientId = URLDecoder.decode(c.getClientId(), Charset.defaultCharset());
          return clientId.equalsIgnoreCase(entity);
        }).findFirst()
        .map()
  }
}
