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

import org.keycloak.component.ComponentModel;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * PKCS11ProviderFactory for creating {@link PKCS11Provider} instances.
 *
 * @author Felix Hellman
 */
public class PKCS11ProviderFactory implements KeyProviderFactory<PKCS11Provider> {

  public static final String PROVIDER_ID = "pkcs-11-hsm-key";
  public static final String LIBRARY_CONFIG_KEY = "pkcs_librarypath";
  public static final String HSMSLOT_NAME_CONFIG_KEY = "pkcs_hsmslot_name";
  public static final String HSMSLOT_ID_CONFIG_KEY = "pkcs_hsmslot_id";
  public static final String HSMSLOT_INDEX_CONFIG_KEY = "pkcs_hsmslot_index";
  public static final String PKCS_BASE_PROVIDER_NAME_CONFIG_KEY = "pkcs_baseProviderName";

  public static final String PKCS_ALIAS_CONFIG_KEY = "pkcs_alias";
  public static final String PKCS_PIN_CONFIG_KEY = "pkcs_pin";

  @Override
  public PKCS11Provider create(final KeycloakSession keycloakSession, final ComponentModel componentModel) {
    return new PKCS11Provider(keycloakSession, componentModel);
  }

  @Override
  public String getHelpText() {
    return "PKCS#11 Implementation";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of(new ProviderConfigProperty(
            LIBRARY_CONFIG_KEY,
        "Library Path",
        "Where PKCS Library is located",
        ProviderConfigProperty.STRING_TYPE,
        ""),
        new ProviderConfigProperty(
            HSMSLOT_NAME_CONFIG_KEY,
            "HSM Slot Name",
            "Name of HSM slot",
            ProviderConfigProperty.STRING_TYPE,
            ""),
        new ProviderConfigProperty(
            HSMSLOT_ID_CONFIG_KEY,
            "HSM Slot ID",
            "ID of HSM slot, may be null",
            ProviderConfigProperty.STRING_TYPE,
            ""),
        new ProviderConfigProperty(
            HSMSLOT_INDEX_CONFIG_KEY,
            "HSM Slot Index",
            "Index of HSM slot, may be null",
            ProviderConfigProperty.INTEGER_TYPE,
            0),
        new ProviderConfigProperty(
            PKCS_BASE_PROVIDER_NAME_CONFIG_KEY,
            "Base Provider Name",
            "The base provider name (if not given, SunPKCS11 is assumed)",
            ProviderConfigProperty.STRING_TYPE,
            ""),
        new ProviderConfigProperty(
            PKCS_ALIAS_CONFIG_KEY,
            "Alias",
            "Alias for the key",
            ProviderConfigProperty.STRING_TYPE,
            ""),
        new ProviderConfigProperty(
            PKCS_PIN_CONFIG_KEY,
            "PIN",
            "PIN for the key",
            ProviderConfigProperty.STRING_TYPE,
            "")
    );
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
