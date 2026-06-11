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

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * Factory for {@link IdpHintOidcIdentityProvider}.
 *
 * <p>Registers the {@value #PROVIDER_ID} identity provider type in Keycloak's SPI registry.
 * Configure this type on any OIDC IdP where {@code kc_idp_hint} must be forwarded from the
 * broker button-click URL to the upstream realm's authorization request.</p>
 *
 * @author David Goldring
 */
public class IdpHintOidcIdentityProviderFactory extends OIDCIdentityProviderFactory {

  /** The provider type identifier used in Keycloak's admin UI and REST API. */
  public static final String PROVIDER_ID = "oidc-idp-hint";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getName() {
    return "OpenID Connect v1.0 (kc_idp_hint forwarding)";
  }

  @Override
  public String getHelpText() {
    return "OIDC identity provider that also forwards kc_idp_hint from the broker login URL "
        + "to the upstream authorization request. Use this instead of the standard OIDC type "
        + "when the upstream realm must receive kc_idp_hint to skip its own login page.";
  }

  @Override
  public IdpHintOidcIdentityProvider create(
      final KeycloakSession session, final IdentityProviderModel model) {
    return new IdpHintOidcIdentityProvider(session, new OIDCIdentityProviderConfig(model));
  }
}
