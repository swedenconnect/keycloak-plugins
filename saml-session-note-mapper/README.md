![Sweden Connect](../docs/images/sweden-connect.png)

# saml-session-note-mapper

Keycloak SPI module providing three identity provider mappers that together propagate a stable
Swedish personal identity number (personnummer) through a two-realm brokering chain:

```
orgiam realm  →  OIDC  →  Transient realm  →  SAML  →  eIDAS / BankID / RefIDP
```

## Background

The Transient realm is configured with `doNotStoreUsers=true`, which means every session creates
an in-memory `LightweightUserAdapter` whose `sub` claim is a fresh `lightweight-<UUID>` per
session. Keycloak's built-in `OIDCIdentityProvider.extractIdentity()` always uses `sub` as the
broker identity ID regardless of any `principalType=ATTRIBUTE` configuration. This causes a
`ModelDuplicateException` on second logins and prevents stable account linking.

The three mappers in this module solve this by extracting the personnummer from the SAML assertion
and propagating it through the token chain so that orgiam uses it as the stable
`identity_provider_identity`.

## Mapper pipeline

### 1. `SamlSessionNoteMapper` — Transient realm, SAML IdP mapper

Reads a SAML attribute from the assertion (configured by name or friendly name) and stores its
value as both a user session note and a user model attribute.

**Why two storage paths?** With `doNotStoreUsers=true`, auth-session user-session notes are not
reliably transferred to the `UserSessionModel` note map. The user model attribute is a fallback
that survives via the `keycloak.userModel` session note.

**Configuration:**

| Property | Default | Description |
|---|---|---|
| Attribute Name | — | SAML attribute name (e.g. `urn:oid:1.2.752.29.4.13`) |
| Friendly Name | — | SAML attribute friendly name (e.g. `personalIdentityNumber`) |
| User Session Note | `transient_personal_identity_number` | Key under which to store the value |

Deploy on: **Transient realm → Identity Providers → `<SAML IdP>` → Mappers**

---

### 2. `SessionNoteClaimMapper` — Transient realm, OIDC protocol mapper

Reads the session note written by `SamlSessionNoteMapper` and emits it as an OIDC claim in the
id-token, access token, and UserInfo response. Falls back to reading from the user model attribute
if the session note is absent.

**Why a dot-free claim name?** Keycloak's `OIDCAttributeMapperHelper` splits claim names on
unescaped dots, turning `personal.identity.number` into a nested JSON object. Using a dot-free
name such as `personalIdentityNumber` avoids this.

**Configuration:**

| Property | Default | Description |
|---|---|---|
| User Session Note | `transient_personal_identity_number` | Session note key to read from |
| Token Claim Name | `personalIdentityNumber` | Claim name to emit in the token |

Deploy on: **Transient realm → Clients → `<orgiam OIDC client>` → Client scopes → Mappers**

---

### 3. `OidcClaimToBrokerIdMapper` — orgiam realm, OIDC IdP mapper

Reads the personnummer claim from the validated id-token received from the Transient realm and
calls both `context.setId(pnr)` and `context.setUsername(pnr)` on the `BrokeredIdentityContext`
before `FederatedIdentityModel` is created.

- `setId(pnr)` ensures `identity_provider_identity` in `FEDERATED_IDENTITY` is the stable
  personnummer rather than the ephemeral `lightweight-<UUID>`.
- `setUsername(pnr)` enables the `Detect existing broker user` First Broker Login authenticator
  to find a pre-provisioned orgiam user by username (requires `pnr-userids: true` in
  iam-admin-app configuration).

**Configuration:**

| Property | Default | Description |
|---|---|---|
| Claim Name | `personalIdentityNumber` | Claim to read from the id-token |

Deploy on: **orgiam realm → Identity Providers → `orgiam.realm` → Mappers**

---

## First Broker Login flow

The orgiam realm must use a custom First Broker Login flow for the `orgiam.realm` OIDC IdP.
The recommended flow ("AutoLinkIdpUser") contains:

| Step | Authenticator | Requirement |
|---|---|---|
| Detect existing broker user | `idp-detect-existing-broker-user` | Required |
| Automatically set existing user | `idp-auto-link` | Required |

**Detect existing broker user** finds the pre-provisioned orgiam user by username=personnummer
(set by `OidcClaimToBrokerIdMapper`) and stores the match in the auth session. If no matching
orgiam user is found, login is denied — unknown users are never auto-created.

**Automatically set existing user** reads the match stored by the previous step and completes
the login without requiring email verification or re-authentication, which is appropriate since
the user has already been authenticated by a Swedish eID.

`Create User If Unique` must **not** be present in this flow, as it would create orgiam accounts
for users who have not been provisioned by iam-admin-app.

---

## Build

```bash
mvn -U -DskipTests clean package
```

(Run from the repository root or from `saml-session-note-mapper/`.)

## Install into Keycloak 26.x

```bash
cp target/saml-session-note-mapper-<version>.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start --optimized
```

## Running tests

```bash
mvn test -pl saml-session-note-mapper
```

---

Copyright &copy; 2026, [Myndigheten för digital förvaltning - Swedish Agency for
Digital Government (DIGG)](https://www.digg.se). Licensed under version 2.0 of the
[Apache License](https://www.apache.org/licenses/LICENSE-2.0).
