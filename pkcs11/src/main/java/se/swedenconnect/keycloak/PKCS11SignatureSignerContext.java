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

import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureSignerContext;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/**
 * Signer Context for PKCS#11 signer.
 *
 * @author Felix Hellman
 */
public class PKCS11SignatureSignerContext implements SignatureSignerContext {

  private final PkiCredential credential;
  private final KeyWrapper wrapper;

  /**
   * Constructor.
   * @param credential
   * @param wrapper
   */
  public PKCS11SignatureSignerContext(final PkiCredential credential, final KeyWrapper wrapper) {
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
  public String getHashAlgorithm() {
    return JavaAlgorithm.getJavaAlgorithmForHash(this.wrapper.getAlgorithmOrDefault());
  }

  @Override
  public byte[] sign(final byte[] data) throws SignatureException {
    try {
      final Signature signature = this.getSignatureInstance();
      signature.initSign(this.credential.getPrivateKey());
      signature.update(data);
      return signature.sign();
    } catch (final Exception e) {
      throw new RuntimeException("Failed to load key or sign", e);
    }
  }

  private Signature getSignatureInstance() throws NoSuchAlgorithmException {
    if (this.wrapper.getType().equals("EC")) {
      return Signature.getInstance("SHA256withECDSA");
    }
    if (this.wrapper.getType().equals("RSA")) {
      return Signature.getInstance("SHA256withRSA");
    }
    throw new IllegalArgumentException("Failed to determine signature algorithm to use for type:%s"
        .formatted(this.wrapper.getType()));
  }
}
