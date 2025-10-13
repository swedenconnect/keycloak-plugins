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

import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureProviderFactory;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.pkcs11.CustomPkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.Pkcs11Credential;
import se.swedenconnect.security.credential.pkcs11.SunPkcs11CertificatesAccessor;
import se.swedenconnect.security.credential.pkcs11.SunPkcs11PrivateKeyAccessor;

import java.util.Objects;
import java.util.Optional;

/**
 * Factory class for creating signature provider for PKCS#11.
 *
 * @author Felix Hellman
 */
public class PKCS11SignatureProviderFactory implements SignatureProviderFactory {

  private static final Logger log = Logger.getLogger(PKCS11SignatureProviderFactory.class);

  @Override
  public SignatureProvider create(final KeycloakSession session) {
    return new PKCS11SignatureProvider(session);
  }

  @Override
  public String getId() {
    return "PKCS11-Signature-Provider";
  }

  /**
   * Creates {@link CustomPkcs11Configuration} from {@link ComponentModel}
   *
   * @param model
   * @return config
   */
  public static CustomPkcs11Configuration fromComponent(final ComponentModel model) {
    final MultivaluedHashMap<String, String> config = model.getConfig();
    try {
      return new CustomPkcs11Configuration(
          config.getFirst(PKCS11ProviderFactory.LIBRARY_CONFIG_KEY),
          config.getFirst(PKCS11ProviderFactory.HSMSLOT_NAME_CONFIG_KEY),
          config.getFirst(PKCS11ProviderFactory.HSMSLOT_ID_CONFIG_KEY),
          Optional.ofNullable(config.getFirst(PKCS11ProviderFactory.HSMSLOT_INDEX_CONFIG_KEY))
              .map(Integer::parseInt).orElse(0),
          config.getFirst(PKCS11ProviderFactory.PKCS_BASE_PROVIDER_NAME_CONFIG_KEY)
      );
    } catch (final Exception e) {
      return null;
    }
  }

  /**
   * Creates {@link PkiCredential} from {@link ComponentModel}
   *
   * @param model
   * @param session
   * @return credential
   */
  public static PkiCredential credentialFromComponent(final ComponentModel model, final KeycloakSession session) {
    final MultivaluedHashMap<String, String> config = model.getConfig();
    final CustomPkcs11Configuration configuration = fromComponent(model);
    if (Objects.isNull(configuration)) {
      return null;
    }
    final String alias = config.getFirst(PKCS11ProviderFactory.PKCS_ALIAS_CONFIG_KEY);
    final String pin = config.getFirst(PKCS11ProviderFactory.PKCS_PIN_CONFIG_KEY);

    return new Pkcs11Credential(
        configuration,
        alias,
        pin.toCharArray(),
        new SunPkcs11PrivateKeyAccessor(),
        new SunPkcs11CertificatesAccessor()
    );
  }

  /**
   * Creates {@link ComponentModel} from {@link KeyWrapper}
   *
   * @param wrapper
   * @param session
   * @return component
   */
  public static ComponentModel fromKeyWrapper(final KeyWrapper wrapper, final KeycloakSession session) {
    final Optional<ComponentModel> component = session.getContext().getRealm().getComponentsStream()
        .filter(key -> key.getProviderId().equalsIgnoreCase(PKCS11ProviderFactory.PROVIDER_ID))
        .filter(key -> key.getId().equalsIgnoreCase(wrapper.getProviderId()))
        .findFirst();

    return component.get();

  }

  /**
   * Lookup of {@link KeyWrapper} from kid
   *
   * @param kid
   * @param session
   * @return wrapper
   */
  public static KeyWrapper getKeyWrapper(final String kid, final KeycloakSession session) {
    final KeyProvider provider = session.getProvider(KeyProvider.class);
    final Optional<KeyWrapper> first = provider.getKeysStream()
        .filter(wrapper -> kid.equalsIgnoreCase(wrapper.getKid()))
        .findFirst();

    final KeyWrapper keyWrapper = first.get();
    return keyWrapper;
  }

  /**
   * Creates {@link KeyWrapper} from {@link ComponentModel}
   *
   * @param model
   * @param session
   * @return wrapper
   */
  public static KeyWrapper fromComponent(final ComponentModel model, final KeycloakSession session) {
    final KeyManager keyManager = session.keys();
    final RealmModel realm = session.getContext().getRealm();
    final Optional<KeyWrapper> first = keyManager.getKeysStream(realm)
        .filter(wrapper -> model.getId().equalsIgnoreCase(wrapper.getProviderId()))
        .findFirst();

    return first.get();
  }
}
