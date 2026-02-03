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
package se.swedenconnect.keycloak;

import com.nimbusds.jose.jwk.JWK;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * PKCS#11 provider implements {@link KeyProvider} interface for supplying keys via hsm to keycloak.
 *
 * @author Felix Hellman
 */
public class PKCS11Provider implements KeyProvider {

  private static final Logger log = Logger.getLogger(PKCS11Provider.class);

  private final KeycloakSession session;
  private final ComponentModel model;

  /**
   * Constructor.
   *
   * @param session
   * @param model
   */
  public PKCS11Provider(final KeycloakSession session, final ComponentModel model) {
    log.infof("Creating new PKCS11Provider %s %s", model.getName(), model.getConfig());
    this.session = session;
    this.model = model;
  }

  @Override
  public Stream<KeyWrapper> getKeysStream() {
    final PkiCredential credential = PKCS11SignatureProviderFactory
        .credentialFromComponent(this.model, this.session);

    if (Objects.isNull(credential)) {
      log.info("HSM Provider returned 0 keys");
      return Stream.of();
    }

    final JWK apply =
        new JwkTransformerFunction().apply(
            credential
        );
    final KeyWrapper t = new KeyWrapper();
    t.setType(apply.getKeyType().getValue());
    t.setKid(apply.getKeyID());
    Optional.ofNullable(apply.toECKey()).ifPresent(ecKey -> {
      t.setCurve(ecKey.getCurve().getName());
    });
    t.setAlgorithm(t.getAlgorithmOrDefault());
    t.setPublicKey(credential.getPublicKey());
    t.setCertificateChain(List.of(credential.getCertificate()));
    t.setUse(KeyUse.SIG);
    t.setStatus(KeyStatus.ACTIVE);
    t.setProviderId(this.model.getId());
    return Stream.of(t);
  }
}
