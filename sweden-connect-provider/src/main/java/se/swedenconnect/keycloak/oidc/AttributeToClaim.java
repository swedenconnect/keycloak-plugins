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
package se.swedenconnect.keycloak.oidc;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Collection of attribute mappings.
 *
 * @author Felix Hellman
 */
public class AttributeToClaim {

  public static List<AttributeClaim> ATTRIBUTE_MAPPINGS = claimMappings();

  private static List<AttributeClaim> claimMappings() {
    final ArrayList<AttributeClaim> attributeClaims = new ArrayList<>();

    attributeClaims.add(
        AttributeClaim.builder(
                "urn:oid:2.5.4.4",
                "family_name"
            ).build()
    );
    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:2.5.4.42",
            "given_name"
        ).build()
    );
    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:2.16.840.1.113730.3.1.241",
            "name"
        ).build()
    );
    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:1.3.6.1.5.5.7.9.3",
            "gender"
        ).build()
    );
    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:1.2.752.29.4.13",
            "https://id.oidc.se/claim/personalIdentityNumber"
        ).build()
    );

    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:1.2.752.201.3.15",
            "https://id.oidc.se/claim/previousCoordinationNumber"
        ).build()
    );

    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:1.3.6.1.5.5.7.9.1",
            "birthdate"
        ).build()
    );

    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:1.2.752.29.6.2.1",
            "employeeHsaId"
        ).build()
    );

    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:1.2.752.201.3.4",
            "prid"
        ).build()
    );

    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:1.2.752.201.3.11",
            "https://id.oidc.se/claim/userSignature"
        ).build()
    );

    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:1.2.752.201.3.10",
            "https://id.oidc.se/claim/userCertificate"
        ).build()
    );

    attributeClaims.add(
        AttributeClaim.builder(
            "urn:oid:1.2.752.201.3.13",
            "https://id.oidc.se/claim/authnEvidence"
        ).build()
    );

    return attributeClaims;
  }

  /**
   * Convert config to list of attribute claims
   * @param config to convert
   * @return list of mappings
   */
  public static List<AttributeClaim> fromConfiguration(final Map<String, String> config) {
    return config
        .entrySet()
        .stream()
        .map(entry -> new AttributeClaim(entry.getKey(), entry.getValue())
    ).toList();
  }
}
