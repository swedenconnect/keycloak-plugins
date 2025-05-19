/*
 * Copyright 2025 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package se.swedenconnect.keycloak;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.yaml.snakeyaml.Yaml;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.InputStream;
import java.net.URI;
import java.util.Map;

/**
 * Test Client for running client credential flows.
 *
 * @author Felix Hellman
 */
public class ClientCredentialTestClient {

  private static final String CONFIGURATION_ERROR_MESSAGE = """
      Failed to read configuration from classpath:config.yml
      please create the file classpath:config.yml with the following contents.
            
      client:
        client-id:
        client-secret:
        token-endpoint:
      """;

  private final ClientConfiguration clientConfiguration;

  /**
   * Constructor.
   * @param clientConfiguration
   */
  public ClientCredentialTestClient(final ClientConfiguration clientConfiguration) {
    this.clientConfiguration = clientConfiguration;
  }

  private static Map<String, String> readClientConfiguration() {
    try (final InputStream config = ClientCredentialTestClient.class
        .getClassLoader().getResourceAsStream("config.yml")) {
      final Yaml yaml = new Yaml();
      final Map<String, Object> load = yaml.load(config);
      return (Map<String, String>) load.get("clientcredential");
    } catch (final Exception e) {
      System.err.println(CONFIGURATION_ERROR_MESSAGE);
      throw new RuntimeException(e);
    }
  }


  /**
   * Program entrypoint
   * @param args for program
   * @throws Exception
   */
  public static void main(final String[] args) throws Exception {
    final Map<String, String> config = readClientConfiguration();
    final ClientCredentialTestClient client = new ClientCredentialTestClient(
        new ClientConfiguration(config)
    );
    final AccessToken accessToken = client.performRequest();
    System.out.println(
        SignedJWT.parse(accessToken.getValue())
            .getJWTClaimsSet()
            .toJSONObject()
            .toString()
    );
  }

  /**
   * Performs token request.
   * @return accessToken
   * @throws Exception
   */
  public AccessToken performRequest() throws Exception {
    final ClientID clientID = new ClientID(this.clientConfiguration.getClientId());
    final Secret clientSecret = new Secret(this.clientConfiguration.getClientSecret());
    final ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

    final URI tokenEndpoint = new URI(this.clientConfiguration.getTokenEndpoint());
    final TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, new ClientCredentialsGrant());
    final SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(null, new TrustManager[]{new NoTrust()}, null);
    final HTTPRequest httpRequest = request.toHTTPRequest();
    httpRequest.setSSLSocketFactory(ctx.getSocketFactory());
    final TokenResponse response = TokenResponse.parse(httpRequest.send());
    return response.toSuccessResponse().getTokens().getAccessToken();
  }
}
