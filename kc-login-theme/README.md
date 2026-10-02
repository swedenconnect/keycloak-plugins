![Sweden Connect](../../docs/images/sweden-connect.png)

# kc-login-theme

Two Keycloak 26.x login themes, packaged as a single provider JAR:

- **`DiggDs`** is identity-provider selection only, no username/password form.
- **`DiggDSPsw`** is `DiggDs`'s look, but with a username/password badge inside the `Legitimering`
  tab.

Both extend the stock `keycloak.v2` login theme and override only what differs. Every other page,
such as password reset and OTP, comes from `keycloak.v2` and takes its colours and typeface from
the stylesheet of the theme in use.

Dark mode is turned off in both, since the reference portal has no dark variant.


## Identity-provider grouping

The alias patterns for the `Tjänstelegitimation` tab are matched in `isServiceIdp()` in each
theme's `login.ftl`. An alias that matches none of them lands in `Legitimering`, so a newly added
identity provider always appears somewhere on the page. Note that a plain `freja` alias (personal
Freja eID) is **not** matched — only `frejaorg` (Freja eID for organisations) counts as a service
credential.

## Contents

Everything is under `src/main/resources/`.

| File | Purpose |
| :--- | :--- |
| `META-INF/keycloak-themes.json` | Tells Keycloak that the JAR holds the themes `DiggDs` and `DiggDSPsw`, both of type `login`. |
| `theme/<name>/login/theme.properties` | Sets the parent theme `keycloak.v2`, turns off dark mode, sets `locales=sv,en` and adds the stylesheet. |
| `theme/DiggDs/login/login.ftl` | The login page: card top bar (language switcher + logo) and the `Legitimering`/`Tjänstelegitimation` tabs. No password form. |
| `theme/DiggDSPsw/login/login.ftl` | The same, plus the `Användarnamn Lösenord` badge and its password form. |
| `theme/DiggDs/login/resources/css/digg-ds.css` | Colours, typeface, the top bar, the tabs and the button styling. |
| `theme/DiggDSPsw/login/resources/css/digg-ds-psw.css` | The same, plus the password badge and the primary submit button, kept in step with `digg-ds.css` by hand. |
| `theme/<name>/login/resources/img/` | DIGG's own logo (the full wordmark, used in `.ds-card-topbar`) and favicon. |
| `theme/<name>/login/resources/fonts/` | Ubuntu 400 and 700, latin and latin-ext (separate copies per theme; Keycloak resource directories are not shared between themes). |
| `theme/DiggDs/login/messages/messages_en.properties`, `messages_sv.properties` | The page title (`loginAccountTitle`), the two tab labels (`scLegitimering`, `scServiceIdp`) and the language switcher's accessible name (`scChangeLanguage`). |
| `theme/DiggDSPsw/login/messages/messages_en.properties`, `messages_sv.properties` | The same keys, plus the password badge label (`scUsernamePassword`). |

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
resolution (see the realm's **Localization** settings for the realm-wide default, and **Language
switcher** above for the globe button). Language selection requires Swedish and English to both be
enabled for the realm, under **Realm settings** →
**Localization**.

The identity providers must already be configured under **Identity providers**; aliases that match
`siths`, `efos` or `frejaorg` land in the `Tjänstelegitimation` tab, everything else lands in
`Legitimering` (see **Identity-provider grouping** above).

## Changing the look

**Both themes** (same base structure, separate resource trees kept in step by hand):

- **Colours, typeface and logo:** edit the design tokens at the top of `digg-ds.css` (`DiggDs`) or
  `digg-ds-psw.css` (`DiggDSPsw`, kept in step with `digg-ds.css` by hand).
- **Which alias counts as a service credential:** edit `isServiceIdp()` in the theme's `login.ftl`.
- **A tab label, or the password badge label:** edit the `scLegitimering`/`scServiceIdp` (both
  themes) or `scUsernamePassword` (`DiggDSPsw` only) key in the theme's `messages` files.
- **The layout of the login page:** edit `login.ftl`.

Any change means a rebuild. For quick iteration against a real Keycloak instance, a copy of the
theme directory can be mounted at
`/opt/keycloak/themes/<theme-name>/login` (`DiggDs` or `DiggDSPsw`). The Docker Compose file already
mounts `compose/config/keycloak/themes` there, and starts Keycloak with theme caching turned off, so
a reload shows the change. Remove that copy again before using the JAR, since two themes with the
same name conflict.

## A note on stability

Each `login.ftl` is a copy of the `login.ftl` of `keycloak.v2`, with the changes described above.
`DiggDSPsw` relies on the macros and variables of that theme (`template.ftl`, `field.ftl`,
`buttons.ftl` and `passkeys.ftl`), since it has a password form to submit; `DiggDs` relies only on
`template.ftl`, since it does not. Both themes' `login.ftl` additionally rely on the `locale` bean
(`locale.current`, `locale.supported[].label`/`.url`) for the language switcher — documented
publicly by Keycloak, but likewise not vendored here to verify statically. Keycloak does not treat
any of these as a stable API. Both themes were written against the `keycloak.v2` login theme of
Keycloak 26.7.3, the version the Compose file runs. On every Keycloak upgrade, compare each
`login.ftl` with the `login.ftl` of the new `keycloak.v2` theme and bring over what has changed.

The title/tab typography and button metrics (colour, radius, shadow, size, font weight — see the
design-token comment at the top of `digg-ds.css`) are matched byte-for-byte to the reference
design's actual rendered page (a Material-UI app), not to DIGG's generic published design tokens,
since that was the explicit goal. If the reference's own styling changes, these values will need
re-measuring against it, not against DIGG's design-token documentation.

---

Copyright &copy; 2026, [Myndigheten för digital förvaltning - Swedish Agency for
Digital Government (DIGG)](https://www.digg.se). Licensed under version 2.0 of the
[Apache License](https://www.apache.org/licenses/LICENSE-2.0).
