# HMAC Attribute Subject Mapper

`HMAC-Attribute-Sub` is an OIDC protocol mapper provided by the
`sweden-connect-provider` module. It computes the OIDC `sub` claim by applying a configured
HMAC to the first available user attribute. It supports ID tokens, access tokens, UserInfo,
token introspection responses, and logout tokens.

## Configuration

Add the **HMAC Attribute Sub Mapper** to the client or to a client scope used by that client.

| Setting | Required | Default | Description |
|---|---:|---|---|
| User Attributes | Yes | — | Ordered list of user attribute names, one per line. The first attribute with a non-null value is used as the HMAC input. |
| HMAC Key | Yes | — | Symmetric key used for the HMAC. See the security warning below. |
| HMAC Algorithm | No | `HmacSHA256` | HMAC algorithm: `HmacSHA256`, `HmacSHA384`, or `HmacSHA512`. |
| Subject Prefix | No | — | Optional text prepended to the encoded digest and separated by `-`. |
| Subject Encoding | No | `Base64` | Encode the digest as standard Base64 or lowercase hexadecimal (`Hex`). |
| Default Subject Type | No | `public` | Use the same subject for all clients (`public`) or a sector-specific subject (`pairwise`). A client can override this default. |

> **Security warning:** Keycloak does not mask the HMAC key in the Admin Console or redact it
> from configuration exports. Anyone who obtains the key can compute subject identifiers for
> guessed user attribute values. Restrict access to the mapper configuration, treat exports
> as sensitive, and do not commit them to source control.

Leaving HMAC Algorithm, Subject Encoding, or Default Subject Type blank uses its default.

For example, the **User Attributes** field can contain:

```text
urn:oid:1.2.752.29.4.13
personalIdentityNumber
```

The first attribute is tried first; the second is only used if the first is absent. A present
empty value is not skipped and will be HMACed as an empty string.

## Public and pairwise subjects

The mapper's **Default Subject Type** setting applies unless the current client has the client
attribute `oidc.subject.type` set to `public` or `pairwise`. This allows a shared client scope
to provide a default while individual clients choose their own subject type.

In public mode, the selected attribute value is the HMAC input. In pairwise mode, the mapper
includes the client's sector identifier along with that value in the input, using an unambiguous
length-prefixed sector encoding. Clients that resolve to the same sector get the same subject for
the same attribute value; clients in different sectors get different subjects.

The host of the OIDC client's `sectorIdentifierUri` is used as the sector when that setting is
configured. Otherwise, Keycloak derives the sector from the registered redirect URIs, which must
resolve to a single host.

Keycloak validates the mapper settings when the mapper is saved. For a mapper saved directly on a
client in effective `pairwise` mode, it also validates the client's sector configuration. If
`sectorIdentifierUri` is configured, Keycloak fetches the JSON list at that URI and checks that it
covers the client's registered redirect URIs. Saving a mapper on a shared client scope cannot
validate individual clients.

## Token behavior

The mapper uses the same subject calculation for ID tokens, access tokens, UserInfo, introspection
responses, and logout tokens. UserInfo places the value in its `sub` claim; the other token
representations use their subject field.

Ensure this mapper runs after any other mapper that can set `sub`; protocol mappers with a higher
priority value run later in Keycloak. The built-in subject mapper has a lower priority, so this
mapper can override its value.

If the mapper cannot compute the subject (for example, because a user attribute is missing or a
pairwise sector cannot be resolved), it logs an error and returns the incoming token unchanged.
Any existing subject is preserved and may not be pairwise. Configure a non-empty HMAC key and
an attribute present on every user for whom tokens are issued.
