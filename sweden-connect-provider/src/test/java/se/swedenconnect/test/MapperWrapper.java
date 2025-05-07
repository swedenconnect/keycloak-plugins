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

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.mockito.Mockito;
import se.swedenconnect.keycloak.oidc.OIDCMapper;
import se.swedenconnect.keycloak.saml.SwedenConnectAttributeMapper;

import java.util.Map;

public class MapperWrapper {
  public MappingTestResult getResult(final TestContext testContext) {

    final OIDCMapper mapper = new OIDCMapper();
    final SwedenConnectAttributeMapper swedenConnectAttributeMapper = new SwedenConnectAttributeMapper();

    swedenConnectAttributeMapper.preprocessFederatedIdentity(
        Mockito.mock(KeycloakSession.class),
        Mockito.mock(RealmModel.class),
        Mockito.mock(IdentityProviderMapperModel.class),
        testContext
    );

    final UserSessionModel mock = Mockito.mock(UserSessionModel.class);
    Mockito.when(mock.getNote(Mockito.anyString())).thenAnswer(a -> {
      final String argument = (String) a.getArgument(0);
      return testContext.getSessionNotes().get(argument);
    });
    final UserModel userModel = Mockito.mock(UserModel.class);
    Mockito.when(userModel.getUsername()).thenReturn("YYYYMMDDXXXX");
    Mockito.when(mock.getUser()).thenReturn(userModel);
    final ProtocolMapperModel model = new ProtocolMapperModel();
    model.setConfig(Map.of("attribute.username.key", "urn:oid:1.2.752.29.4.13"));
    final ClientSessionContext csc = Mockito.mock(ClientSessionContext.class);
    final AuthenticatedClientSessionModel acsm = Mockito.mock(AuthenticatedClientSessionModel.class);
    Mockito.when(csc.getScopeString(true)).thenReturn("oidc");
    Mockito.when(csc.getClientSession()).thenReturn(acsm);
    final ClientModel client = Mockito.mock(ClientModel.class);
    Mockito.when(acsm.getClient()).thenReturn(client);
    Mockito.when(client.getClientId()).thenReturn("testclient");
    final AccessToken accessToken = mapper.transformAccessToken(
        new AccessToken(),
        model,
        Mockito.mock(KeycloakSession.class),
        mock,
        csc
    );

    final IDToken idToken = mapper.transformIDToken(
        new IDToken(),
        model,
        Mockito.mock(KeycloakSession.class),
        mock,
        csc
    );

    final AccessToken userInfo = mapper.transformUserInfoToken(new AccessToken(),
        Mockito.mock(ProtocolMapperModel.class),
        Mockito.mock(KeycloakSession.class),
        mock,
        csc);

    return new MappingTestResult(testContext.getSamlAttributes(), idToken, accessToken, userInfo);
  }
}
