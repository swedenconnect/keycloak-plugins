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

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.IdentityProviderAuthenticator;
import org.keycloak.models.ProtocolMapperModel;
import se.swedenconnect.keycloak.oidc.IdpFilterMapper;

import java.util.Map;
import java.util.Optional;

/**
 * Authenticator for IDP selection/filtering.
 *
 * @author Felix Hellman
 */
public class IdpSelectorAuthenticator extends IdentityProviderAuthenticator {

  private static final Logger log = Logger.getLogger(IdpSelectorAuthenticator.class);

  @Override
  public void authenticate(final AuthenticationFlowContext context) {
    if (!this.selectDefaultProvider(context)) {
      context.success();
    }
  }

  private Optional<ProtocolMapperModel> getFilterMapperScope(final AuthenticationFlowContext context) {
    return context
        .getAuthenticationSession()
        .getClient()
        .getProtocolMappersStream()
        .filter(mapper -> mapper.getProtocolMapper()
            .equals("IDP-FILTER"))
        .findFirst();
  }


  private boolean selectDefaultProvider(final AuthenticationFlowContext context) {
    final Optional<String> redirected = this.getFilterMapperScope(context)
        .flatMap(model -> {
          final Map<String, String> config = model.getConfig();
          log.infof("Default provider config %s", config);
          return Optional.ofNullable(config.get(IdpFilterMapper.DEFAULT_IDENTITY_PROVIDER));
        });
    redirected
        .ifPresent(providerAlias -> {
          log.infof("Sending redirect to %s", providerAlias);
          this.redirect(context, providerAlias);
        });
    return redirected.isPresent();
  }
}
