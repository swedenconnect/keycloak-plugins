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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.DefaultKeyManager;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import se.swedenconnect.oidf.common.entity.jwt.FederationSigner;
import se.swedenconnect.oidf.common.entity.jwt.JWKFederationSigner;
import se.swedenconnect.oidf.common.entity.jwt.SignerFactory;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Signer factory for keycloak.
 *
 * @author Felix Hellman
 */
public class KeycloakSignerFactory implements SignerFactory {

  private final RSAKey key;
  private final List<JWK> jwks = new ArrayList<>();

  /**
   * Constructor.
   * @param session
   */
  public KeycloakSignerFactory(final KeycloakSession session) {
    final KeyManager keyManager = new DefaultKeyManager(session);
    final KeyWrapper rs256 = keyManager.getActiveKey(session.getContext().getRealm(), KeyUse.SIG, "RS256");
    this.key = KeycloakSignerFactory.buildKey(rs256);

    keyManager.getKeysStream(session.getContext().getRealm(), KeyUse.SIG, "RS256")
        .collect(Collectors.toSet())
        .stream()
        .map(KeycloakSignerFactory::buildKey)
        .forEach(this.jwks::add);

    keyManager.getKeysStream(session.getContext().getRealm(), KeyUse.ENC, "RS256")
        .collect(Collectors.toSet())
        .stream()
        .map(KeycloakSignerFactory::buildKey)
        .forEach(this.jwks::add);
  }

  private static RSAKey buildKey(final KeyWrapper rs256) {
    try {
      return new RSAKey.Builder((RSAPublicKey) rs256.getPublicKey())
          .privateKey((RSAPrivateKey) rs256.getPrivateKey())
          .keyIDFromThumbprint()
          .build();
    } catch (final Exception e) {
      throw new RuntimeException("Failed to build internal key", e);
    }
  }

  @Override
  public FederationSigner createSigner() {
    return new JWKFederationSigner(this.key);
  }

  @Override
  public JWK getSignKey() {
    return this.key;
  }

  @Override
  public JWKSet getSignKeys() {
    return new JWKSet(this.key);
  }

  /**
   * @return keys to be used for metadata
   */
  public JWKSet getMetadataKeys() {
    return new JWKSet(this.jwks);
  }
}
