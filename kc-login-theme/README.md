![Sweden Connect](../../docs/images/sweden-connect.png)

# kc-login-theme

Two Keycloak 26.x login themes, packaged as a single provider JAR:

- **`DiggDs`** is identity-provider selection only, no username/password form, styled after DIGG's
  own discovery service at <https://iam.digg.se/ds> (a muted green-grey card per provider), with
  DIGG's own logo in the header.
- **`DiggDSPsw`** is `DiggDs`'s look and icons, but with the identity providers first and the
  username/password form folded behind a last toggle card.

Both extend the stock `keycloak.v2` login theme and override only what differs. Every other page,
such as password reset and OTP, comes from `keycloak.v2` and takes its colours and typeface from
the stylesheet of the theme in use.

`DiggDs` and `DiggDSPsw` share the same alias-to-icon matching (see below); pick whichever layout
(with or without a password form) fits the realm.

## DiggDs

The login page (`login.ftl`) is only the list of identity providers, as cards; there is no
username/password form, regardless of whether the realm allows one. Colours (the muted green card
background, `#5a6751` accent), the card layout and the Ubuntu typeface follow DIGG's discovery
service at <https://iam.digg.se/ds>. The header shows **DIGG's own logo and favicon**, taken from
<https://www.digg.se>, sized the same as on the discovery service (35px). Each card also shows a
brand icon; see **Identity-provider icons** below.

Dark mode is turned off, since the discovery service has no dark variant.

## DiggDSPsw

The login page (`login.ftl`) lists the identity providers first, as DIGG-style cards (same as
`DiggDs`, including the brand icons). The last item, labelled **Username/Password**, is a card that
unfolds the username and password form — a native HTML `details` element, open from the start when
the realm has no identity provider or after a failed login. Colours, typeface and the header
(DIGG's own logo and favicon) are the same as `DiggDs`.

Dark mode is turned off, since the discovery service has no dark variant.

## Identity-provider icons

Both themes show a brand icon per identity provider, chosen by matching the provider's **alias** in
the Admin Console against a fixed set of substrings (case-insensitive), in `idpIconFile()` in each
theme's `login.ftl`:

| Alias contains | Icon |
| :--- | :--- |
| `bankid` | `img/idp/bankid.svg` |
| `siths` | `img/idp/siths.svg` |
| `efos` | `img/idp/efos.png` |
| `freja` | `img/idp/freja.svg` |
| `eidas` or `foreign` | `img/idp/foreign-eid.svg` |
| (no match) | `img/idp/default.svg` |

An alias that matches none of the named patterns falls back to a generic icon, so a newly added
identity provider never breaks the page; add a pattern and drop the matching icon into
`resources/img/idp/` to give it a real one. `bankid.svg`, `siths.svg`, `efos.png`, `freja.svg` and
`foreign-eid.svg` are each provider's own official logo, taken from the same URLs DIGG's discovery
service (<https://iam.digg.se/ds>) itself serves them from; `default.svg` is a generic placeholder
mark, not any provider's logo. The two themes keep separate, identical copies of the icon files,
since Keycloak resource directories are not shared between themes.

## Contents

Everything is under `src/main/resources/`.

| File | Purpose |
| :--- | :--- |
| `META-INF/keycloak-themes.json` | Tells Keycloak that the JAR holds the themes `DiggDs` and `DiggDSPsw`, both of type `login`. |
| `theme/DiggDs/login/theme.properties` | Sets the parent theme `keycloak.v2`, turns off dark mode and adds the stylesheet. |
| `theme/DiggDs/login/login.ftl` | The login page: identity-provider list only, with the alias-to-icon matching described above. |
| `theme/DiggDs/login/resources/css/digg-ds.css` | Colours, typeface and the identity-provider card layout. |
| `theme/DiggDs/login/resources/img/` | DIGG's own logo and favicon (header) and `img/idp/`, the bundled provider icons. |
| `theme/DiggDs/login/resources/fonts/` | Ubuntu 400 and 700, latin and latin-ext. |
| `theme/DiggDs/login/messages/messages_en.properties`, `messages_sv.properties` | The subtitle above the identity-provider list, `scSelectIdp`, and the page title, `loginAccountTitle`. |
| `theme/DiggDSPsw/login/theme.properties` | Sets the parent theme `keycloak.v2`, turns off dark mode and adds the stylesheet. |
| `theme/DiggDSPsw/login/login.ftl` | The login page: identity providers first (with the alias-to-icon matching), the password form behind the last toggle card. |
| `theme/DiggDSPsw/login/resources/css/digg-ds-psw.css` | Colours, typeface, logo and card shapes, matching `DiggDs`, plus the password-toggle card and filled submit button. |
| `theme/DiggDSPsw/login/resources/img/` | DIGG's own logo and favicon (header) and `img/idp/`, the bundled provider icons. |
| `theme/DiggDSPsw/login/resources/fonts/` | Ubuntu 400 and 700, latin and latin-ext (a copy of the same files as `DiggDs`). |
| `theme/DiggDSPsw/login/messages/messages_en.properties`, `messages_sv.properties` | The label of the toggle card, `scUsernamePassword`, and the page title, `loginAccountTitle`. |

Theme names have no space, because Keycloak uses them as directory names.

## Build

```bash
mvn -U -DskipTests clean package
```

(Run from the repository root or from `keycloak/kc-login-theme/`.)

The JAR holds resources only. There is no Java code, and nothing is filtered, so the fonts and the logo
reach the JAR byte for byte.

The module is part of the plugin distribution ZIP that `keycloak/plugin-distribution` assembles, so
`compose/keycloak-scripts/install-keycloak-plugins.sh` builds it and installs it next to the other
plugin JARs.

## Install into Keycloak 26.x

```bash
cp target/kc-login-theme-<version>.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start --optimized
```

Restart Keycloak after the JAR has been added. A Keycloak that runs with `start --optimized` needs
`kc.sh build` first, as for any provider.

## Configure in the Admin Console

1. Go to **Realm settings** → **Themes**.
2. Set **Login theme** to `DiggDs` or `DiggDSPsw`.
3. Save.

To give a single client another look than the rest of the realm, set the login theme on the client
instead, under **Clients** → *client* → **Advanced**.

Both themes list `locales=sv,en` in `theme.properties`, with `loginAccountTitle=Logga in` set as the
Swedish page title. Swedish is used whenever the browser's `Accept-Language` header, a `kc_locale`
parameter or a saved locale selects it; otherwise Keycloak falls back through its normal locale
resolution (see the realm's **Localization** settings for the realm-wide default). Language selection
requires Swedish and English to both be enabled for the realm, under **Realm settings** →
**Localization**.

The identity providers must already be configured under **Identity providers**; aliases that match
the patterns in `idpIconFile()` (see above) get their real icon, others get the generic fallback.

## Changing the look

**Both themes** (same structure, separate resource trees kept in step by hand):

- **Colours, typeface and logo:** edit the design tokens at the top of `digg-ds.css` (`DiggDs`) or
  `digg-ds-psw.css` (`DiggDSPsw`, kept in step with `digg-ds.css` by hand).
- **Which alias gets which icon:** edit `idpIconFile()` in the theme's `login.ftl`; drop the icon file
  itself into `resources/img/idp/` (see **Identity-provider icons** above).
- **The subtitle above the list (`DiggDs`) or the toggle card label (`DiggDSPsw`):** edit the
  `scSelectIdp` or `scUsernamePassword` key in the theme's `messages` files.
- **The layout of the login page:** edit `login.ftl`.

Any change means a rebuild. For quick iteration on the CSS, a copy of the theme directory can be
mounted at `/opt/keycloak/themes/<theme-name>/login` (`DiggDs` or `DiggDSPsw`). The Docker Compose
file already mounts `compose/config/keycloak/themes` there, and starts Keycloak with theme caching
turned off, so a reload shows the change. Remove that copy again before using the JAR, since two
themes with the same name conflict.

## A note on stability

Each `login.ftl` is a copy of the `login.ftl` of `keycloak.v2`, with the changes described above.
`DiggDSPsw` relies on the macros and variables of that theme (`template.ftl`, `field.ftl`,
`buttons.ftl` and `passkeys.ftl`), since it has a password form to submit; `DiggDs` relies only on
`template.ftl`, since it does not. Keycloak does not treat any of these as a stable API. Both themes
were written against the `keycloak.v2` login theme of Keycloak 26.7.3, the version the Compose file
runs. On every Keycloak upgrade, compare each `login.ftl` with the `login.ftl` of the new
`keycloak.v2` theme and bring over what has changed.

---

Copyright &copy; 2026, [Myndigheten för digital förvaltning - Swedish Agency for
Digital Government (DIGG)](https://www.digg.se). Licensed under version 2.0 of the
[Apache License](https://www.apache.org/licenses/LICENSE-2.0).
