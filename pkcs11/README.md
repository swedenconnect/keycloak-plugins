# PKCS 11 Module for Keycloak ️

## ⚠️This plugin is a work in progress, please see issues before using. ⚠️

This module adds support for PKCS#11 to keycloak.

## Installation

To use PKSC#11 you will need a library (.so) installed for your container.
Provided is an example using softhsm.

### Custom docker image

Below is an example on how you can build a custom keycloak instance with softhsm.

```dockerfile
FROM almalinux:9 AS builder

RUN dnf install -y libstdc++ openssl softhsm openssl-devel --allowerasing
RUN dnf clean all

FROM quay.io/keycloak/keycloak:latest AS final

COPY --from=builder /usr/bin/softhsm2-util /usr/bin/softhsm2-util
COPY --from=builder /usr/lib64/pkcs11/libsofthsm2.so /usr/lib64/pkcs11/libsofthsm2.so
COPY --from=builder /usr/lib64/libssl.so.* /usr/lib64/
COPY --from=builder /usr/lib64/libcrypto.so.* /usr/lib64/
COPY --from=builder /usr/lib64/libstdc++.so.* /usr/lib64/

USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

### Configuring Keycloak

In your realm, navigate to Realm settings -> Keys -> Providers

Add a new pkcs-11-hsm-key provider which requires the following settings
```
Name: < Name of this instance >
Library Path: < Absolute path to .so lib, in our example this is "/usr/lib64/pkcs11/libsofthsm2.so" > 
HSM Slot Name: < Slot name >
HSM Slot ID: < use ID or index not both >
HSM Slot Index: < use ID or index not both >
Base Provider Name: < e.g. SunPKCS11 >
Alias: < key alias/label >
PIN: < key pin >
```