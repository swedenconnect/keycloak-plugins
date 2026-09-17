![Logo](docs/images/sweden-connect.png)

# Keycloak Plugins

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) 
![Version](https://img.shields.io/badge/Version-_0.6.0--SNAPSHOT-yellow)

Keycloak Plugins for use with Sweden Connect Federation

-----

## About

This repository consists of a keycloak plugins to use in accordance to [Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/).

## Documentation

- [Release notes](docs/release-notes.md)
- [Sweden Connect Provider](docs/sweden-connect-provider.MD)
- [Keycloak Login Customizer](docs/keycloak-login-customizer.MD)
- [Tools](docs/tools.MD)
- [IdP-Hint OIDC Provider](idp-hint-oidc-provider/README.md) (parked, see below)
- [SAML Session Note Mapper](saml-session-note-mapper/README.md) (parked, see below)
- [Integration Tests](integration-tests/README.md)

Requires **Keycloak 26.7** or later. See the
[release notes](docs/release-notes.md) for the compatibility change in 0.5.0.

### Parked modules

`idp-hint-oidc-provider` and `saml-session-note-mapper` are not built by the default reactor and
are not released. The code stays here until a new home is decided for it. Build them with:

```bash
mvn -Pparked verify
```

That keeps them compiling, and their unit tests running, against the Keycloak version this
repository targets.

## Contributing

Pull requests are welcome. See the [Contributor Guidelines](CONTRIBUTING.md) for details.

## License

The Keycloak Plugins is Open Source software released under the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

-----

Copyright &copy; 2025-2026, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).