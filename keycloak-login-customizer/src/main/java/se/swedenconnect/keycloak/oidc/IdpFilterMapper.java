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

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.AccessToken;

import java.util.List;

/**
 * IDP Filter Mapper for selecting IDP per client.
 *
 * @author Felix Hellman
 */
public class IdpFilterMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

  @Override
  public AccessToken transformAccessToken(
      final AccessToken token,
      final ProtocolMapperModel mapper,
      final KeycloakSession session,
      final UserSessionModel userSession,
      final ClientSessionContext context) {

    return super.transformAccessToken(token, mapper, session, userSession, context);
  }

  public static String DEFAULT_IDENTITY_PROVIDER = "ATTRIBUTE.IDP.DEFAULT";

  @Override
  public String getDisplayCategory() {
    return "IDP Filter Mapper";
  }

  @Override
  public String getDisplayType() {
    return "IDP Filter Mapper";
  }

  @Override
  public String getHelpText() {
    return "IDP Filter Mapper";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    final ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();

    return builder.property()
        .name(DEFAULT_IDENTITY_PROVIDER)
        .label("Default Idp")
        .type(ProviderConfigProperty.STRING_TYPE)
        .add()
        .build();
  }

  @Override
  public String getId() {
    return "IDP-FILTER";
  }
}
