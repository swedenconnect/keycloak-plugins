/*
 * Copyright 2026 Sweden Connect
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
 */
package se.swedenconnect.keycloak.broker;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IdpHintOidcIdentityProvider}.
 *
 * @author David Goldring
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IdpHintOidcIdentityProviderTest {

  @Mock
  private KeycloakSession session;

  @Mock
  private AuthenticationRequest request;

  @Mock
  private HttpRequest httpRequest;

  @Mock
  private UriInfo uriInfo;

  @Mock
  private MultivaluedMap<String, String> queryParams;

  @Mock
  private UriBuilder uriBuilder;

  private IdpHintOidcIdentityProvider provider;

  @BeforeEach
  void setUp() {
    final IdentityProviderModel model = new IdentityProviderModel();
    model.setAlias("transient-realm");
    final OIDCIdentityProviderConfig config = new OIDCIdentityProviderConfig(model);
    this.provider = spy(new IdpHintOidcIdentityProvider(this.session, config));

    when(this.request.getHttpRequest()).thenReturn(this.httpRequest);
    when(this.httpRequest.getUri()).thenReturn(this.uriInfo);
    when(this.uriInfo.getQueryParameters()).thenReturn(this.queryParams);
  }

  @Test
  void hintPresent_appendedToUriBuilder() {
    when(this.queryParams.getFirst(IdpHintOidcIdentityProvider.KC_IDP_HINT)).thenReturn("bankid");

    this.provider.appendIdpHintParam(this.uriBuilder, this.request);

    verify(this.uriBuilder).queryParam(IdpHintOidcIdentityProvider.KC_IDP_HINT, "bankid");
  }

  @Test
  void hintAbsent_uriBuilderUnchanged() {
    when(this.queryParams.getFirst(IdpHintOidcIdentityProvider.KC_IDP_HINT)).thenReturn(null);

    this.provider.appendIdpHintParam(this.uriBuilder, this.request);

    verify(this.uriBuilder, never()).queryParam(any(), any());
  }

  @Test
  void hintBlank_uriBuilderUnchanged() {
    when(this.queryParams.getFirst(IdpHintOidcIdentityProvider.KC_IDP_HINT)).thenReturn("   ");

    this.provider.appendIdpHintParam(this.uriBuilder, this.request);

    verify(this.uriBuilder, never()).queryParam(any(), any());
  }

  @Test
  void hintEmpty_uriBuilderUnchanged() {
    when(this.queryParams.getFirst(IdpHintOidcIdentityProvider.KC_IDP_HINT)).thenReturn("");

    this.provider.appendIdpHintParam(this.uriBuilder, this.request);

    verify(this.uriBuilder, never()).queryParam(any(), any());
  }

  @Test
  void appendIdpHintParam_returnsUriBuilder() {
    when(this.queryParams.getFirst(IdpHintOidcIdentityProvider.KC_IDP_HINT)).thenReturn("siths");

    final UriBuilder result = this.provider.appendIdpHintParam(this.uriBuilder, this.request);

    org.junit.jupiter.api.Assertions.assertSame(this.uriBuilder, result);
  }
}
