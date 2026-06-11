![Sweden Connect](../docs/images/sweden-connect.png)

# idp-hint-oidc-provider

A Keycloak 26.x custom OIDC identity provider that forwards the `kc_idp_hint` query parameter
from the broker button-click URL to the upstream realm's authorization request, enabling
single-page IdP selection without an extra login-page redirect.

## What it does

In a two-realm brokering chain such as `orgiam → OIDC → Transient → SAML IdP`, users can be
presented with IdP-selection buttons (BankID, RefIDP, etc.) on the orgiam login page. Clicking
a button appends `kc_idp_hint=<alias>` to the broker URL, telling the Transient realm which
SAML IdP to use — skipping the Transient realm's own login page entirely.

Keycloak's built-in `forwardParameters` mechanism for OIDC identity providers reads
`kc_idp_hint` from the auth-session note that was populated from the *original* client request,
not from the broker redirect URL. This means the hint set by an IdP-selection button is
silently discarded and never reaches the Transient realm.

This provider overrides `createAuthorizationUrl()` to also inspect the **current HTTP request's
query parameters** for `kc_idp_hint`, appending it to the upstream authorization URL when
present. The result is that a button click on the orgiam login page reliably routes the user to
the correct SAML IdP in the Transient realm with no extra redirects.

**Provider ID:** `oidc-idp-hint`
**Display name:** `OpenID Connect v1.0 (kc_idp_hint forwarding)`

## Build

```bash
mvn -U -DskipTests clean package
```

(Run from the repository root or from `idp-hint-oidc-provider/`.)

## Install into Keycloak 26.x

```bash
cp target/idp-hint-oidc-provider-<version>.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start --optimized
```

## Configure in the Admin Console

Use this provider **instead of** the standard `OpenID Connect v1.0` provider when the upstream
realm must receive `kc_idp_hint` from the broker URL.

1. In the orgiam realm, go to **Identity Providers** → **Add provider** → select
   **OpenID Connect v1.0 (kc_idp_hint forwarding)**.
2. Configure it identically to a standard OIDC identity provider (discovery URL, client ID,
   client secret / `private_key_jwt`, etc.).
3. In the provider's **Advanced** settings, add `kc_idp_hint` to **Forwarded query parameters**
   so Keycloak also forwards hints arriving from the initial client request (belt-and-suspenders
   alongside the URL-parameter forwarding this provider adds).
4. On the orgiam login page theme, add one button per upstream SAML IdP. Each button should
   include `kc_idp_hint=<transient-realm-idp-alias>` in the broker redirect URL. The provider
   will forward this to the Transient realm, which will skip its login page and go directly to
   the named SAML IdP.

---

Copyright &copy; 2026, [Myndigheten för digital förvaltning - Swedish Agency for
Digital Government (DIGG)](https://www.digg.se). Licensed under version 2.0 of the
[Apache License](https://www.apache.org/licenses/LICENSE-2.0).
