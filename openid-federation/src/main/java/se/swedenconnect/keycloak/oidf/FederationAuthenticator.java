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

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Authenticator.
 *
 * @author Felix Hellman
 */
public class FederationAuthenticator implements Authenticator {


  @Override
  public void authenticate(final AuthenticationFlowContext context) {
    context.getSession().getContext().getUserSession().setNote("trust_marks", null);
  }

  @Override
  public void action(final AuthenticationFlowContext context) {

  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(final KeycloakSession session, final RealmModel realm, final UserModel user) {
    return false;
  }

  @Override
  public void setRequiredActions(final KeycloakSession session, final RealmModel realm, final UserModel user) {

  }

  @Override
  public void close() {

  }
}
