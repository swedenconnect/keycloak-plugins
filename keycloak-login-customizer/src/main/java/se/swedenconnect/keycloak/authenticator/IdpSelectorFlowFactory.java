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
package se.swedenconnect.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernameFormFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Authenticator factory for idp selector.
 *
 * @author Felix Hellman
 */
public class IdpSelectorFlowFactory extends UsernameFormFactory {
  @Override
  public String getDisplayType() {
    return "idp-selector";
  }

  @Override
  public String getReferenceCategory() {
    return super.getReferenceCategory();
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return super.getRequirementChoices();
  }


  @Override
  public String getHelpText() {
    return "Idp Selector";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of();
  }

  @Override
  public Authenticator create(final KeycloakSession session) {
    return new IdpSelectorAuthenticator();
  }

  @Override
  public void init(final Config.Scope config) {
    super.init(config);
  }

  @Override
  public void postInit(final KeycloakSessionFactory factory) {
    super.postInit(factory);
  }

  @Override
  public void close() {
    super.close();
  }

  @Override
  public String getId() {
    return "Idp-Selector";
  }
}
