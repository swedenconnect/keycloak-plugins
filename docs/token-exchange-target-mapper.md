# Token Exchange Target Mapper

`oidc-token-exchange-target-mapper` ("Token exchange resource and audience") is an OIDC protocol mapper provided by
the `sweden-connect-provider` module. It makes Keycloak's standard token exchange (RFC 8693) follow section 2.3 of
the [Ena chaining profile](https://ena-infrastructure.github.io/specifications/ena-oauth2-chaining.html): a target
(`resource` per RFC 8707, or `audience`) that identifies the downstream protected resource is enough, and the issued
token carries the scopes relevant to that resource.

Keycloak 26.8 accepts `resource` in a token exchange request but ignores it. It also only puts an audience in `aud`
if a requested (or default) scope of the exchanging client has an audience mapper for it, so `resource` or
`audience` without the matching `scope` fails. This mapper fills both gaps. The `resource-mapper` and executor in
[rfc8707-resource-indicators.md](rfc8707-resource-indicators.md) cover the authorization code and refresh grants; this
mapper covers token exchange.

## Behaviour

Only token exchange requests (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`) are affected.
`resource` and `audience` are read from the form body and the query string. A parameter can be repeated, or hold
several values separated by commas (the `Rfc8707PostBodyFilter` joins repeated `resource` values with commas).

- **Target to scope.** For each target, the mapper looks for an `oidc-audience-mapper` with that audience (client
  audience or custom audience) among the exchanging client's own mappers and its default and optional client scopes.
  Such a scope is taken as the client's entitlement to the target (Ena 2.3.1). The target is added to `aud`, and the
  scope to the token's `scope` claim, even if the request did not ask for the scope. Only the audience mapper of a
  scope found this way is applied; its other mappers do not run, because Keycloak did not add the scope to the
  session.
- **Scopes for other resources.** Scopes that only give audiences other than the targets are removed from the
  `scope` claim (Ena 2.4). Scopes without an audience mapper are kept.
- **Permission scopes** (every token exchange, also without a target). Client scopes of the exchanging client that
  have no mappers, such as `resource:read`, are only kept in the `scope` claim if the subject token has them (Ena
  2.3.1, no upscoping). Keycloak already requires them to be requested. Scopes with mappers are not touched, since
  removing the name would leave their claims in the token.
- **Narrowing.** `aud` becomes exactly the requested resources. `audience` narrows `aud` through Keycloak itself.
- **Errors.** A `resource` that no scope gives, or that drops out because `resource` and `audience` name different
  resources, gives no token: the response is `{"error":"invalid_target","error_description":"Requested resource not
  available: ..."}` without `access_token`. A protocol mapper cannot set the HTTP status, so it is **200**. Keycloak
  itself rejects an `audience` that no scope gives (400 `invalid_request`) and one that is not a client ID (400
  `invalid_client`).

The `scope` field of the token response JSON is set by Keycloak after the mappers have run, so it can differ from the
access token's `scope` claim.

## Phases

The mapper has priority 50 (`ProtocolMapperUtils.PRIORITY_SCRIPT_MAPPER`), audience mappers 0. Its access token phase
therefore runs after the audience mappers, and before Keycloak checks `audience`: it adds the targets to `aud` and
fixes the `scope` claim. Keycloak narrows `aud` to `audience` after all mappers have run, so the narrowing to the
requested resources happens in the token response phase. There the mapper narrows `aud`, signs the access token again,
and, if the response has an ID token, signs that again with a new `at_hash`.

## Configuration

Add the mapper to a client scope that is a default scope of every client that does token exchange (or to each
client). Turn on **Add to access token**, **Add to ID token** and **Add to token response**: all three phases are
needed. The mapper sets no claim of its own.

| Setting | Default | Description |
|---|---|---|
| Remove scopes for other resources (`remove.other.resource.scopes`) | on | Remove scopes whose audience mappers only give other audiences when a target is requested. |
| Permission scopes must be in the subject token (`require.subject.token.scopes`) | on | Remove mapper-less client scopes that the subject token does not have. |

Realm import example:

```json
{
  "name": "resource-indicator",
  "protocol": "openid-connect",
  "attributes": { "include.in.token.scope": "false", "display.on.consent.screen": "false" },
  "protocolMappers": [
    {
      "name": "token exchange resource and audience",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-token-exchange-target-mapper",
      "config": {
        "access.token.claim": "true",
        "id.token.claim": "true",
        "access.tokenResponse.claim": "true"
      }
    }
  ]
}
```

Debug logging (`se.swedenconnect.keycloak.oidc.TokenExchangeTargetMapper:debug`) shows the targets, `aud` and `scope`
of each exchange.
