![Sweden Connect](../../docs/images/sweden-connect.png)

# login-theme

Four Keycloak 26.x login themes, packaged as a single provider JAR:

- **`SwedenconnectIdpPsw`** gives the login page the look of
  <https://sandbox.swedenconnect.se/home/>, and puts the identity providers first, with the
  username and password form behind a last button.
- **`SwedenconnectDS`** is identity-provider selection only, no username/password form, in the same
  Sweden Connect look as `SwedenconnectIdpPsw`, with a brand icon on each identity-provider button.
- **`DiggDs`** is identity-provider selection only, no username/password form, styled after DIGG's
  own discovery service at <https://iam.digg.se/ds> instead (a muted green-grey card per provider,
  rather than `SwedenconnectIdpPsw`'s filled button), with DIGG's own logo in the header.
- **`DiggDSPsw`** is `DiggDs`'s look and icons, but with the identity providers first and the
  username/password form folded behind a last toggle card — the same layout `SwedenconnectIdpPsw`
  uses, just in the DIGG visual style.

All four extend the stock `keycloak.v2` login theme and override only what differs. Every other
page, such as password reset and OTP, comes from `keycloak.v2` and takes its colours and typeface
from the stylesheet of the theme in use.

`SwedenconnectDS`, `DiggDs` and `DiggDSPsw` share the same alias-to-icon matching (see below); pick
whichever combination of visual style and layout (with or without a password form) fits the realm.

## SwedenconnectIdpPsw

The login page (`login.ftl`) lists the identity providers first, as buttons. The last button, labelled
**Username/Password**, unfolds the username and password form. The form is open from the start when
the realm has no identity provider, and after a failed login, so that the error message is never
hidden behind a closed button. The button is a native HTML `details` element, so it works without
JavaScript and can be operated from the keyboard.

Logo, colours, typeface and button shapes are taken from <https://sandbox.swedenconnect.se/home/>:

- The Sweden Connect logo and the favicon.
- Ubuntu 400 and 700, served from the theme.
- The colour tokens of the site, declared under the same names in `swedenconnect.css`, so that a later
  comparison against the site stays easy.
- A filled button for the identity providers and an outlined one for the username and password toggle,
  with the dotted focus outline that is the most recognisable detail of the site.

Dark mode is turned off, since the site has no dark variant.

## SwedenconnectDS

The login page (`login.ftl`) is only the list of identity providers, as the same filled buttons as
`SwedenconnectIdpPsw` (`sc-btn sc-btn-filled`, see `swedenconnect-ds.css`); there is no
username/password form, regardless of whether the realm allows one. Colours, typeface and button
shapes are the same Sweden Connect values as `SwedenconnectIdpPsw`, including the header logo. Each
button also shows a brand icon; see **Identity-provider icons** below.

Dark mode is turned off, since the site has no dark variant.

## DiggDs

The login page (`login.ftl`) is only the list of identity providers, as cards; there is no
username/password form, regardless of whether the realm allows one. Colours (the muted green card
background, `#5a6751` accent), the card layout and the Ubuntu typeface follow DIGG's discovery
service at <https://iam.digg.se/ds>. Unlike the other two themes, the header shows **DIGG's own
logo and favicon**, taken from <https://www.digg.se>, sized the same as on the discovery service
(35px). Each card also shows a brand icon; see **Identity-provider icons** below.

Dark mode is turned off, since the discovery service has no dark variant.

## DiggDSPsw

The login page (`login.ftl`) lists the identity providers first, as DIGG-style cards (same as
`DiggDs`, including the brand icons). The last item, labelled **Username/Password**, is a card that
unfolds the username and password form — the same pattern `SwedenconnectIdpPsw` uses (a native HTML
`details` element, open from the start when the realm has no identity provider or after a failed
login), styled to match the other cards instead of `SwedenconnectIdpPsw`'s outlined button. Colours,
typeface and the header (DIGG's own logo and favicon) are the same as `DiggDs`.

Dark mode is turned off, since the discovery service has no dark variant.

## Identity-provider icons

`SwedenconnectDS`, `DiggDs` and `DiggDSPsw` all show a brand icon per identity provider, chosen by
matching the provider's **alias** in the Admin Console against a fixed set of substrings
(case-insensitive), in `idpIconFile()` in each theme's `login.ftl`:

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
service (<https://iam.digg.se/ds>) itself serves them from; `default.svg` is a Sweden Connect–coloured
placeholder mark, not any provider's logo. The three themes keep separate, identical copies of the
icon files, since Keycloak resource directories are not shared between themes.

## Contents

Everything is under `src/main/resources/`.

| File | Purpose |
| :--- | :--- |
| `META-INF/keycloak-themes.json` | Tells Keycloak that the JAR holds the themes `SwedenconnectIdpPsw`, `SwedenconnectDS`, `DiggDs` and `DiggDSPsw`, all of type `login`. |
| `theme/SwedenconnectIdpPsw/login/theme.properties` | Sets the parent theme `keycloak.v2`, turns off dark mode and adds the stylesheet. |
| `theme/SwedenconnectIdpPsw/login/login.ftl` | The login page: identity providers first, the password form behind the last button. |
| `theme/SwedenconnectIdpPsw/login/resources/css/swedenconnect.css` | Colours, typeface, logo and button shapes. |
| `theme/SwedenconnectIdpPsw/login/resources/img/` | The Sweden Connect logo and the favicon. |
| `theme/SwedenconnectIdpPsw/login/resources/fonts/` | Ubuntu 400 and 700, latin and latin-ext. |
| `theme/SwedenconnectIdpPsw/login/messages/messages_en.properties`, `messages_sv.properties` | The label of the toggle button, `scUsernamePassword`. |
| `theme/SwedenconnectDS/login/theme.properties` | Sets the parent theme `keycloak.v2`, turns off dark mode and adds the stylesheet. |
| `theme/SwedenconnectDS/login/login.ftl` | The login page: identity-provider list only, with the alias-to-icon matching described above. |
| `theme/SwedenconnectDS/login/resources/css/swedenconnect-ds.css` | Colours, typeface, logo and button shapes, matching `SwedenconnectIdpPsw`, plus the icon layout inside each button. |
| `theme/SwedenconnectDS/login/resources/img/` | The Sweden Connect logo (header) and `img/idp/`, the bundled provider icons. |
| `theme/SwedenconnectDS/login/resources/fonts/` | Ubuntu 400 and 700, latin and latin-ext (a copy of the same files as `SwedenconnectIdpPsw`; Keycloak resource directories are not shared between themes). |
| `theme/SwedenconnectDS/login/messages/messages_en.properties`, `messages_sv.properties` | The subtitle above the identity-provider list, `scSelectIdp`. |
| `theme/DiggDs/login/theme.properties` | Sets the parent theme `keycloak.v2`, turns off dark mode and adds the stylesheet. |
| `theme/DiggDs/login/login.ftl` | The login page: identity-provider list only, with the same alias-to-icon matching. |
| `theme/DiggDs/login/resources/css/digg-ds.css` | Colours, typeface and the identity-provider card layout. |
| `theme/DiggDs/login/resources/img/` | DIGG's own logo and favicon (header) and `img/idp/`, the bundled provider icons. |
| `theme/DiggDs/login/resources/fonts/` | Ubuntu 400 and 700, latin and latin-ext (a copy of the same files as the other two themes). |
| `theme/DiggDs/login/messages/messages_en.properties`, `messages_sv.properties` | The subtitle above the identity-provider list, `scSelectIdp`. |
| `theme/DiggDSPsw/login/theme.properties` | Sets the parent theme `keycloak.v2`, turns off dark mode and adds the stylesheet. |
| `theme/DiggDSPsw/login/login.ftl` | The login page: identity providers first (with the alias-to-icon matching), the password form behind the last toggle card. |
| `theme/DiggDSPsw/login/resources/css/digg-ds-psw.css` | Colours, typeface, logo and card shapes, matching `DiggDs`, plus the password-toggle card and filled submit button. |
| `theme/DiggDSPsw/login/resources/img/` | DIGG's own logo and favicon (header) and `img/idp/`, the bundled provider icons. |
| `theme/DiggDSPsw/login/resources/fonts/` | Ubuntu 400 and 700, latin and latin-ext (a copy of the same files as the other themes). |
| `theme/DiggDSPsw/login/messages/messages_en.properties`, `messages_sv.properties` | The label of the toggle card, `scUsernamePassword`. |

Theme names have no space, because Keycloak uses them as directory names.

## Build

```bash
mvn -U -DskipTests clean package
```

(Run from the repository root or from `keycloak/login-theme/`.)

The JAR holds resources only. There is no Java code, and nothing is filtered, so the fonts and the logo
reach the JAR byte for byte.

The module is part of the plugin distribution ZIP that `keycloak/plugin-distribution` assembles, so
`compose/keycloak-scripts/install-keycloak-plugins.sh` builds it and installs it next to the other
plugin JARs.

## Install into Keycloak 26.x

```bash
cp target/login-theme-<version>.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start --optimized
```

Restart Keycloak after the JAR has been added. A Keycloak that runs with `start --optimized` needs
`kc.sh build` first, as for any provider.

## Configure in the Admin Console

1. Go to **Realm settings** → **Themes**.
2. Set **Login theme** to `SwedenconnectIdpPsw`, `SwedenconnectDS`, `DiggDs` or `DiggDSPsw`.
3. Save.

To give a single client another look than the rest of the realm, set the login theme on the client
instead, under **Clients** → *client* → **Advanced**.

Check the Swedish text by adding `?kc_locale=sv` to the login URL. It requires that the language is
enabled for the realm, under **Realm settings** → **Localization**. Otherwise the English text is shown.

For `SwedenconnectDS`, `DiggDs` and `DiggDSPsw`, the identity providers must already be configured
under **Identity providers**; aliases that match the patterns in `idpIconFile()` (see above) get
their real icon, others get the generic fallback.

## Changing the look

**SwedenconnectIdpPsw:**

- **Colours, typeface and logo:** edit the design tokens at the top of `swedenconnect.css`.
- **The label of the toggle button:** edit the `scUsernamePassword` key in the two `messages` files.
- **The layout of the login page:** edit `login.ftl`.

**SwedenconnectDS and DiggDs** (same structure, separate resource trees kept in step by hand):

- **Colours, typeface and logo:** edit the design tokens at the top of `swedenconnect-ds.css`
  (`SwedenconnectDS`) or `digg-ds.css` (`DiggDs`).
- **Which alias gets which icon:** edit `idpIconFile()` in the theme's `login.ftl`; drop the icon file
  itself into `resources/img/idp/` (see **Identity-provider icons** above).
- **The subtitle above the list:** edit the `scSelectIdp` key in the theme's two `messages` files.
- **The layout of the login page:** edit `login.ftl`.

**DiggDSPsw:**

- **Colours, typeface and logo:** edit the design tokens at the top of `digg-ds-psw.css` (kept in
  step with `digg-ds.css` by hand).
- **Which alias gets which icon:** edit `idpIconFile()` in `login.ftl`; drop the icon file itself into
  `resources/img/idp/` (see **Identity-provider icons** above).
- **The label of the toggle card:** edit the `scUsernamePassword` key in the two `messages` files.
- **The layout of the login page:** edit `login.ftl`.

Any change means a rebuild. For quick iteration on the CSS, a copy of the theme directory can be
mounted at `/opt/keycloak/themes/<theme-name>/login` (`SwedenconnectIdpPsw`, `SwedenconnectDS`,
`DiggDs` or `DiggDSPsw`). The Docker Compose file already mounts `compose/config/keycloak/themes`
there, and starts Keycloak with theme caching turned off, so a reload shows the change. Remove that
copy again before using the JAR, since two themes with the same name conflict.

## A note on stability

Each `login.ftl` is a copy of the `login.ftl` of `keycloak.v2`, with the changes described above.
`SwedenconnectIdpPsw` and `DiggDSPsw` rely on the macros and variables of that theme (`template.ftl`,
`field.ftl`, `buttons.ftl` and `passkeys.ftl`), since both have a password form to submit;
`SwedenconnectDS` and `DiggDs` rely only on `template.ftl`, since neither does. Keycloak does not
treat any of these as a stable API. All four themes were written against the `keycloak.v2` login
theme of Keycloak 26.7.3, the version the Compose file runs. On every Keycloak upgrade, compare each
`login.ftl` with the `login.ftl` of the new `keycloak.v2` theme and bring over what has changed.

---

Copyright &copy; 2026, [Myndigheten för digital förvaltning - Swedish Agency for
Digital Government (DIGG)](https://www.digg.se). Licensed under version 2.0 of the
[Apache License](https://www.apache.org/licenses/LICENSE-2.0).
