![Sweden Connect](../../docs/images/sweden-connect.png)

# kc-login-theme

Two Keycloak 26.x login themes, packaged as a single provider JAR:

- **`DiggDs`**
- **`DiggDSPsw`**

Both are styled after DIGG's own discovery service at <https://iam.digg.se/ds> and have the same
page structure (see below); they are kept as two separate theme names so a realm can be pointed at
either one under **Realm settings** → **Themes**, and so the two can diverge again later without
disturbing whichever realms already use one of them. Both extend the stock `keycloak.v2` login
theme and override only what differs. Every other page, such as password reset and OTP, comes from
`keycloak.v2` and takes its colours and typeface from the stylesheet of the theme in use.

Dark mode is turned off in both, since the discovery service has no dark variant.

## Page structure

The login page (`login.ftl`) splits the realm's configured identity providers into two groups by
**alias** (case-insensitive substring match):

| Alias contains | Group |
| :--- | :--- |
| `siths`, `efos` or `frejaorg` | e-service credential |
| anything else | personal e-identification |

- **Personal e-identification** (e.g. BankID, foreign eID) is listed directly at the top, as plain
  text buttons — no provider logos are shown.
- **`E-tjänste legitimation`** is a badge that only appears when the realm has at least one
  e-service-credential provider configured. Clicking it expands the list of those providers, in the
  same text-only style as the personal list above.
- **`Användarnamn Lösenord`** is a second badge, shown whenever the realm allows password login
  (`realm.password`). Clicking it expands the username/password form. If the realm has *no*
  identity providers configured at all (neither group), the form is shown directly instead, with no
  badge to unfold. The badge opens automatically after a failed username/password login, so the
  error is never hidden behind a closed badge.

Both badges are native HTML `<details>` elements, so they need no JavaScript and are operable from
the keyboard.

## Identity-provider grouping

The alias patterns for the `E-tjänste legitimation` badge are matched in `isServiceIdp()` in each
theme's `login.ftl`. An alias that matches none of them is treated as personal e-identification, so
a newly added identity provider always appears somewhere on the page. Note that a plain `freja`
alias (personal Freja eID) is **not** matched — only `frejaorg` (Freja eID for organisations) counts
as an e-service credential.

## Contents

Everything is under `src/main/resources/`.

| File | Purpose |
| :--- | :--- |
| `META-INF/keycloak-themes.json` | Tells Keycloak that the JAR holds the themes `DiggDs` and `DiggDSPsw`, both of type `login`. |
| `theme/<name>/login/theme.properties` | Sets the parent theme `keycloak.v2`, turns off dark mode, sets `locales=sv,en` and adds the stylesheet. |
| `theme/<name>/login/login.ftl` | The login page: personal identity providers, the `E-tjänste legitimation` badge and the `Användarnamn Lösenord` badge, as described above. |
| `theme/DiggDs/login/resources/css/digg-ds.css` | Colours, typeface and the selection-block/badge layout. |
| `theme/DiggDSPsw/login/resources/css/digg-ds-psw.css` | The same layout, kept in step with `digg-ds.css` by hand. |
| `theme/<name>/login/resources/img/` | DIGG's own logo and favicon, shown in the page header. |
| `theme/<name>/login/resources/fonts/` | Ubuntu 400 and 700, latin and latin-ext (separate copies per theme; Keycloak resource directories are not shared between themes). |
| `theme/<name>/login/messages/messages_en.properties`, `messages_sv.properties` | The page title (`loginAccountTitle`), the subtitle above the personal list (`scSelectIdp`), and the two badge labels (`scServiceIdp`, `scUsernamePassword`). |

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
`siths`, `efos` or `frejaorg` land in the `E-tjänste legitimation` badge, everything else is listed
at the top (see **Identity-provider grouping** above).

## Changing the look

**Both themes** (same structure, separate resource trees kept in step by hand):

- **Colours, typeface and logo:** edit the design tokens at the top of `digg-ds.css` (`DiggDs`) or
  `digg-ds-psw.css` (`DiggDSPsw`, kept in step with `digg-ds.css` by hand).
- **Which alias counts as an e-service credential:** edit `isServiceIdp()` in the theme's `login.ftl`.
- **The subtitle above the list, or the two badge labels:** edit the `scSelectIdp`, `scServiceIdp` or
  `scUsernamePassword` key in the theme's `messages` files.
- **The layout of the login page:** edit `login.ftl`.

Any change means a rebuild. For quick iteration on the CSS, a copy of the theme directory can be
mounted at `/opt/keycloak/themes/<theme-name>/login` (`DiggDs` or `DiggDSPsw`). The Docker Compose
file already mounts `compose/config/keycloak/themes` there, and starts Keycloak with theme caching
turned off, so a reload shows the change. Remove that copy again before using the JAR, since two
themes with the same name conflict.

## A note on stability

Each `login.ftl` is a copy of the `login.ftl` of `keycloak.v2`, with the changes described above.
Both themes rely on the macros and variables of that theme (`template.ftl`, `field.ftl`,
`buttons.ftl` and `passkeys.ftl`), since both have a password form to submit. Keycloak does not
treat any of these as a stable API. Both themes were written against the `keycloak.v2` login theme
of Keycloak 26.7.3, the version the Compose file runs. On every Keycloak upgrade, compare each
`login.ftl` with the `login.ftl` of the new `keycloak.v2` theme and bring over what has changed.

---

Copyright &copy; 2026, [Myndigheten för digital förvaltning - Swedish Agency for
Digital Government (DIGG)](https://www.digg.se). Licensed under version 2.0 of the
[Apache License](https://www.apache.org/licenses/LICENSE-2.0).
