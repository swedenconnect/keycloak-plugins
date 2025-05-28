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

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import se.swedenconnect.oidf.resolver.Resolver;
import se.swedenconnect.oidf.resolver.tree.EntityStatementTreeLoader;
import se.swedenconnect.oidf.resolver.tree.resolution.DFSExecution;
import se.swedenconnect.oidf.resolver.tree.resolution.ScheduledStepRecoveryStrategy;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Factory.
 *
 * @author Felix Hellman
 */
public class FederationAuthenticatorFactory implements AuthenticatorFactory {

  public static final String TRUST_ANCHOR_KEY = "trust.anchor";
  public static final String RESOLVER_KEY = "resolver";
  public final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
  private final Map<String, Resolver> realmToResolverMap = new ConcurrentHashMap<>();
  private Resolver resolver;
  private static final Logger log = Logger.getLogger(FederationAuthenticator.class);

  @Override
  public String getDisplayType() {
    return "OpenID-Federation";
  }

  @Override
  public String getReferenceCategory() {
    return "OpenID-Federation";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return new AuthenticationExecutionModel.Requirement[]{
        AuthenticationExecutionModel.Requirement.REQUIRED
    };
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public String getHelpText() {
    return "OpenID-Federation";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
        .property()
        .name(TRUST_ANCHOR_KEY)
        .label("Trust Anchor")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("Help text")
        .required(true)
        .add()
        .build();
  }

  @Override
  public Authenticator create(final KeycloakSession session) {
    log.infof("Created federation authenticator for %s", session.getContext().getRealm());
    return new FederationAuthenticator();
  }

  @Override
  public void init(final Config.Scope config) {
    log.infof("Init federation authenticator for %s", config);
    config.getPropertyNames().forEach( p -> log.infof("Property %s", p));
  }

  @Override
  public void postInit(final KeycloakSessionFactory factory) {
    log.info("Job has been scheduled");
    this.job(factory);
    this.scheduler.schedule(() -> {
      )
      this.job(factory);
    }, 10, TimeUnit.MINUTES);
  }

  private void job(final KeycloakSessionFactory factory) {
    KeycloakModelUtils.runJobInTransaction(factory, session -> {
      log.info("Starting scheduled job");
      session.realms()
          .getRealmsStream()
          .forEach(realm -> {
            log.infof("REALM %s", realm.getName());
          });
    });
  }

  @Override
  public void close() {

  }

  @Override
  public String getId() {
    return "OpenID-Federation";
  }
}
