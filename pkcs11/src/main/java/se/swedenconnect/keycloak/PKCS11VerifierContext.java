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
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.Signature;

/**
 * Verifier Context for PKCS#11.
 *
 * @author Felix Hellman
 */
public class PKCS11VerifierContext implements SignatureVerifierContext {

  private final PkiCredential credential;
  private final KeyWrapper wrapper;

  /**
   * Constructor.
   * @param credential
   * @param wrapper
   */
  public PKCS11VerifierContext(
      final PkiCredential credential,
      final KeyWrapper wrapper) {

    this.credential = credential;
    this.wrapper = wrapper;
  }

  @Override
  public String getKid() {
    return this.wrapper.getKid();
  }

  @Override
  public String getAlgorithm() {
    return this.wrapper.getAlgorithm();
  }

  @Override
  public boolean verify(final byte[] data, final byte[] signatureData) throws VerificationException {
    try {
      final Signature signature = Signature.getInstance("%swit%s".formatted(
          JavaAlgorithm.getJavaAlgorithmForHash(this.wrapper.getAlgorithmOrDefault()),
          this.getAlgorithm())
      );
      signature.initVerify(this.credential.getPublicKey());
      signature.update(data);
      return signature.verify(signatureData);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }
}
