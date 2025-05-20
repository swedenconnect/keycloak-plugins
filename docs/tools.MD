# Tools
This module contains clients for authorization code flow and client credentials flow in addition to a mock authorization server.

## Config

### Authorization Code Flow

To use the authorization code flow client we need the following parameters.

```yaml
client:
  client-id: 
  client-secret: 
  auth-endpoint: 
  token-endpoint: 
  userinfo-endpoint: 
```

This can either be configured directly into the code or by reading a yaml file from `classpath:/config.yml`

```java
    final Map<String, String> client = TestClient.readClientConfiguration();
    final TestClient testClient = new TestClient(new ClientConfiguration(client), false);
    //The parameter for startAuth is a customizer for modifying the auth request
    testClient.startAuth(a -> {});
```

### Client Credentials

To use client credentials flow the following parameters needs to be configured.
**Notice that the main key is different.** 

```yaml
clientcredential:
  client-id: 
  client-secret: 
  token-endpoint: 
```

```java
final Map<String, String> config = ClientCredentialTestClient.readClientConfiguration();
    final ClientCredentialTestClient client = new ClientCredentialTestClient(
        new ClientConfiguration(config)
    );
    final AccessToken accessToken = client.performRequest();
```