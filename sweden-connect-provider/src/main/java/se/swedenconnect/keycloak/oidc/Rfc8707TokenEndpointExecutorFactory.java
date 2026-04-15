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

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

import java.util.List;

/**
 * Factory for {@link Rfc8707TokenEndpointExecutor}.
 *
 * <p>Register this factory in a Keycloak client policy profile to enable RFC 8707
 * {@code resource} indicator validation at the token endpoint. The executor must
 * be paired with the {@code resource-authenticator} authentication-flow step (which
 * validates the {@code resource} parameter at the authorization endpoint and stores
 * the result in the client-session note {@code auth_resource_validated}) and the
 * {@code resource-mapper} protocol mapper (which reads the validated resource to set
 * the {@code aud} and {@code scope} claims in the access token).
 *
 * @author Felix Hellman
 */
public class Rfc8707TokenEndpointExecutorFactory implements ClientPolicyExecutorProviderFactory {

  /**
   * Provider ID used to reference this executor in Keycloak client policy profiles.
   */
  public static final String PROVIDER_ID = "rfc8707-resource-indicator";

  @Override
  public ClientPolicyExecutorProvider create(final KeycloakSession session) {
    return new Rfc8707TokenEndpointExecutor(session);
  }

  @Override
  public void init(final Config.Scope config) {
  }

  @Override
  public void postInit(final KeycloakSessionFactory factory) {
  }

  @Override
  public void close() {
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getHelpText() {
    return "Validates RFC 8707 resource indicator parameters at the token endpoint. "
        + "Returns invalid_target when the requested resource is not permitted. "
        + "Works with resource-authenticator (auth flow) and resource-mapper (protocol mapper).";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of();
  }
}
