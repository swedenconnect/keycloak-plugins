![Sweden Connect](../docs/images/sweden-connect.png)

# integration-tests

End-to-end integration tests that boot a real Keycloak of the targeted version
(`keycloak.version` in the root POM) with every plugin jar mounted and drive the plugins the
way a browser and a relying party would.

The tests need a running Docker (or compatible) daemon. When none is available, they are skipped,
not failed.

## What is covered

### `ProviderRegistrationIT`

Asserts that all provider IDs in the repository register on the running server, that
`ProxyProviderFactory` won the ServiceLoader race for `keycloak-oidc`, and that no provider load
errors appear in the server log. This is the cheapest guard against a `META-INF/services` entry or
a shaded-jar problem that compiles clean but breaks at load time.

### `BrokeredLoginIT`

Configures three realms in the one container and walks complete brokered logins through the
plugins with a scripted HTTP client (`Browser`), then asserts on what a client actually receives:

```
idp  - Keycloak as a SAML IdP, asserting the Sweden Connect attributes (urn:oid:...) for "anna"
op   - Keycloak as an OIDC OP, emitting the Sweden Connect claims for the same user
sp   - the realm under test: brokers to the two above through this repository's providers and
       mappers, and issues tokens through the Sweden Connect protocol mappers
```

| Test | Path exercised |
|---|---|
| `samlBrokeredLoginPersistsUserAndPropagatesPersonalIdentityNumber` | SAML broker, persisted users: user creation, names, federated link, personnummer via saml-session-note-mapper |
| `samlBrokeredLoginWithTransientUsersIssuesSwedenConnectClaims` | SAML broker with `doNotStoreUsers=true` (the Sweden Connect proxy mode): the full Sweden-Connect claim set and the acr |
| `oidcProxyLoginForwardsScopesAndIssuesSwedenConnectClaims` | ProxyProvider forwarding the Sweden Connect scopes upstream, Sweden-Connect-OP mapping the returned claims |
| `idpHintProviderForwardsHintFromBrokerUrl` | idp-hint-oidc-provider forwarding `kc_idp_hint` from the broker button URL |
| `cancelledSamlResponseReturnsAccessDeniedToTheClient` | SwedenConnectSAMLEndpoint turning the Sweden Connect cancel status into `error=access_denied` |
| `spMetadataCarriesSwedenConnectExtensions` | Sweden-Connect-SAML-Mapper acting as a metadata updater |

The SAML brokers are configured not to validate signatures, so the Keycloak-issued (and, for the
cancel test, hand-built) SAML responses are accepted without a signing key. The Sweden Connect
proxy realms deploy with `doNotStoreUsers=true`; the transient test is the one that mirrors that.

## Run

```bash
# from the repository root: builds the plugin jars and runs both IT classes
mvn -pl integration-tests -am verify

# just the integration tests, using already-built jars
mvn -pl integration-tests verify
```

On failure the Keycloak container log is written to
`integration-tests/target/keycloak-container.log`, since the container is gone by the time the
failsafe report is read.

---

Copyright &copy; 2026, [Myndigheten för digital förvaltning - Swedish Agency for
Digital Government (DIGG)](https://www.digg.se). Licensed under version 2.0 of the
[Apache License](https://www.apache.org/licenses/LICENSE-2.0).
