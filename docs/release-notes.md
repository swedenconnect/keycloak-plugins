![Sweden Connect](images/sweden-connect.png)

# Keycloak Plugins - Release Notes

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Version](https://img.shields.io/badge/Version-_0.5.0-yellow)

Releases made before this file was introduced are not listed here. See the
[repository tags](https://github.com/swedenconnect/keycloak-plugins/tags) for their history.

---

### Version 0.5.0

**Date:** 2026-09-16

**Availability.** This version is published to the internal Nexus only. The artifacts are not on
Maven Central; see the 0.6.0 notes for the work that publication requires.

- **The plugins now target Keycloak 26.7 and no longer support 26.4 or 26.2.** Keycloak 26.7
  splits `IdentityProvider`: the user-authentication half moved to the new
  `UserAuthenticationIdentityProvider` interface, and the nested `AuthenticationCallback` type
  moved with it. `SwedenConnectSAMLIdentityProvider`, `SwedenConnectSAMLEndpoint` and
  `ProxyProvider` reference it from its new home. `SignatureProviderFactory` also gained an
  abstract `getJwkPrivateKeyClaims()`, used to reject externally supplied JWKs that carry private
  key material; `PKCS11SignatureProviderFactory` reports the union of the RSA and EC claim sets,
  since an HSM key handled by this provider is either RSA or EC.

  **Upgrade action required.** Upgrade the Keycloak server to 26.7 before deploying these JARs.
  Both changes are source-incompatible with 26.2 and 26.4, which have neither
  `UserAuthenticationIdentityProvider` nor the private JWK claim constants. This is why the
  release carries a new minor version rather than a patch: unlike the previous Keycloak bump
  (26.2.5 to 26.4.6 in 0.4.9), which was a drop-in, a server left on an older version will fail
  at provider load or on first use.

  **Deployment.** Copy the new JARs to `/opt/keycloak/providers/`. A `start --optimized`
  installation needs an explicit `kc.sh build` afterwards.

- **`keycloak-saml-core` is no longer bundled in the provider assembly.** The shaded
  `sweden-connect-provider` artifact packaged a copy of a library the server already provides,
  which risked the deployed plugin binding to a different version of the SAML core classes than
  the server itself uses. It is now excluded and taken from the server runtime.

- **New `integration-tests` module boots a real Keycloak with every plugin mounted.** Two test
  classes run against a container of the version the build targets, so a release that compiles
  cleanly but breaks at runtime is caught before it ships. The module is part of the reactor and
  runs under `mvn verify`; it skips itself, rather than failing, when no Docker daemon is
  available. See [Integration Tests](../integration-tests/README.md).

  `ProviderRegistrationIT` asserts that every provider ID in the repository registers on the
  running server, that `ProxyProviderFactory` won the `ServiceLoader` race for `keycloak-oidc`,
  and that no provider load errors appear in the server log.

  `BrokeredLoginIT` configures a SAML IdP realm, an OIDC OP realm and a consuming realm, then
  drives complete brokered logins with a scripted HTTP client and asserts on the tokens, the
  UserInfo response, the persisted user and the published SP metadata. It covers the SAML broker
  with persisted and with transient users, the OIDC proxy scope forwarding, `kc_idp_hint`
  forwarding, the Sweden Connect cancel status, and the SAML metadata extensions.

- **Documented: full Sweden Connect claim propagation requires `doNotStoreUsers=true`.** The
  `SAML_ATTRIBUTES_JSON` user session note that the Sweden Connect protocol mapper reads is set on
  the authentication session, and Keycloak's first-broker-login `resetFlow` clears it. For
  transient users the mapper repopulates the values as attributes on the lightweight user, so the
  claims survive; for persisted users they do not. This is long-standing behaviour rather than a
  change in this release, and it matches how the Sweden Connect proxy realms are deployed. The
  personnummer carried by `saml-session-note-mapper` is unaffected in both modes, because that
  mapper also writes a user model attribute in `importNewUser`.

---

Copyright &copy; 2025-2026, [Myndigheten för digital förvaltning - Swedish Agency for
Digital Government (DIGG)](https://www.digg.se). Licensed under version 2.0 of the
[Apache License](https://www.apache.org/licenses/LICENSE-2.0).
