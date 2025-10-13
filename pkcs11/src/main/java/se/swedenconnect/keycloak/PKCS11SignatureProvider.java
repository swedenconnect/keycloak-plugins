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

import org.keycloak.common.VerificationException;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import se.swedenconnect.security.credential.PkiCredential;

import java.util.Optional;

/**
 * PKCS#11 Signature provider.
 *
 * @author Felix Hellman
 */
public class PKCS11SignatureProvider implements SignatureProvider {

  private final KeycloakSession session;

  /**
   * Constructor.
   * @param session
   */
  public PKCS11SignatureProvider(final KeycloakSession session) {
    this.session = session;
  }

  @Override
  public SignatureSignerContext signer() throws SignatureException {

    final Optional<ComponentModel> key = this.session.getContext().getRealm().getComponentsStream()
        .filter(c -> c.getProviderId().equalsIgnoreCase(PKCS11ProviderFactory.PROVIDER_ID))
        .findFirst();

    final PkiCredential credential = PKCS11SignatureProviderFactory
        .credentialFromComponent(key.get(), this.session);

    return new PKCS11SignatureSignerContext(
        credential,
        PKCS11SignatureProviderFactory.fromComponent(key.get(), this.session)
    );
  }

  @Override
  public SignatureSignerContext signer(final KeyWrapper keyWrapper) throws SignatureException {
    final Optional<ComponentModel> key = this.session.getContext().getRealm().getComponentsStream()
        .filter(c -> c.getProviderId().equalsIgnoreCase(PKCS11ProviderFactory.PROVIDER_ID))
        .filter(c -> keyWrapper.getProviderId().equalsIgnoreCase(c.getId()))
        .findFirst();

    final PkiCredential credential = PKCS11SignatureProviderFactory
        .credentialFromComponent(key.get(), this.session);

    return new PKCS11SignatureSignerContext(credential, keyWrapper);
  }

  @Override
  public SignatureVerifierContext verifier(final String kid) throws VerificationException {
    final KeyWrapper wrapper = PKCS11SignatureProviderFactory.getKeyWrapper(kid, this.session);
    final ComponentModel componentModel = PKCS11SignatureProviderFactory.fromKeyWrapper(wrapper, this.session);
    return new PKCS11VerifierContext(
        PKCS11SignatureProviderFactory.credentialFromComponent(componentModel, this.session),
        wrapper
    );
  }

  @Override
  public SignatureVerifierContext verifier(final KeyWrapper keyWrapper) throws VerificationException {
    final ComponentModel componentModel = PKCS11SignatureProviderFactory.fromKeyWrapper(keyWrapper, this.session);
    return new PKCS11VerifierContext(
        PKCS11SignatureProviderFactory.credentialFromComponent(componentModel, this.session),
        keyWrapper
    );
  }

  @Override
  public boolean isAsymmetricAlgorithm() {
    return true;
  }
}
