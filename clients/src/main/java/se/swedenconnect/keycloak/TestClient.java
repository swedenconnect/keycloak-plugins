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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.yaml.snakeyaml.Yaml;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Test Utility for debugging keycloak plugins.
 * Will send and auth request (via browser) towards keycloak and host a callback endpoint.
 * When the callback endpoint has been called the server will shut down.
 *
 * @author Felix Hellman
 */
public class TestClient implements HttpHandler {

  private static final String CONFIGURATION_ERROR_MESSAGE = """
      Failed to read configuration from classpath:config.yml
      please create the file classpath:config.yml with the following contents.
            
      client:
        client-id:
        client-secret:
        auth-endpoint:
        token-endpoint:
        userinfo-endpoint:
      """;

  private final HttpServer server;
  private final State state = new State();
  private final ClientConfiguration clientConfiguration;

  /**
   * Constructor.
   * @param clientConfiguration
   * @throws IOException
   */
  public TestClient(final ClientConfiguration clientConfiguration) throws IOException {
    this.server = HttpServer.create(new InetSocketAddress(1337), 0);
    this.clientConfiguration = clientConfiguration;
  }

  /**
   * Program entrypoint.
   * @param args
   * @throws URISyntaxException
   * @throws IOException
   */
  public static void main(final String[] args) throws URISyntaxException, IOException {
    final Map<String, String> client = readClientConfiguration();
    final TestClient testClient = new TestClient(new ClientConfiguration(client));
    testClient.startAuthorization();
  }

  private static Map<String, String> readClientConfiguration() {
    try (final InputStream config = TestClient.class.getClassLoader().getResourceAsStream("config.yml")) {
      final Yaml yaml = new Yaml();
      final Map<String, Object> load = yaml.load(config);
      return (Map<String, String>) load.get("client");
    } catch (final Exception e) {
      System.err.println(CONFIGURATION_ERROR_MESSAGE);
      throw new RuntimeException(e);
    }
  }

  private String prettyPrint(final String json) throws Exception {
    final ObjectMapper objectMapper = new ObjectMapper();
    final Object jsonObject = objectMapper.readValue(json, Object.class);
    return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
  }

  private void startAuthorization() throws URISyntaxException, IOException {
    final ClientID clientID = new ClientID(this.clientConfiguration.getClientId());
    final URI callback = new URI("http://localhost:1337/cb");

    final Nonce nonce = new Nonce();

    final OIDCClaimsRequest claims = new OIDCClaimsRequest()
        .withUserInfoClaimsRequest(
            new ClaimsSetRequest(
                List.of(new ClaimsSetRequest.Entry("given_name")
                    .withClaimRequirement(ClaimRequirement.VOLUNTARY))
            )
        )
        .withIDTokenClaimsRequest(
            new ClaimsSetRequest(
                List.of(new ClaimsSetRequest.Entry("name_of_dog")
                    .withClaimRequirement(ClaimRequirement.ESSENTIAL))
            )
        );
    final AuthenticationRequest request = new AuthenticationRequest.Builder(
        new ResponseType("code"),
        new Scope(
            "openid",
            "https://id.oidc.se/scope/naturalPersonInfo",
            "https://id.oidc.se/scope/naturalPersonNumber",
            "https://id.oidc.se/scope/naturalPersonOrgId"
        ),
        clientID,
        callback)
        .endpointURI(new URI(this.clientConfiguration.getAuthEndpoint()))
        .state(this.state)
        .nonce(nonce)
        .claims(claims)
        .resource(URI.create("https://api.local.test"))
        .build();

    System.out.println(request.toURI());

    openWebpage(request.toURI());
    this.server.createContext("/cb", this);
    this.server.start();
  }

  private static boolean openWebpage(final URI uri) {
    final Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
    if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
      try {
        desktop.browse(uri);
        return true;
      } catch (final Exception e) {
        e.printStackTrace();
      }
    }
    return false;
  }

  @Override
  public void handle(final HttpExchange exchange) throws IOException {
    try {
      final AuthenticationResponse response = AuthenticationResponseParser.parse(
          new URI("http://localhost:1337/cb?" + exchange.getRequestURI().toString()));

      if (response instanceof AuthenticationErrorResponse) {
        System.err.println(response.toErrorResponse().getErrorObject());
        return;
      }


      final AuthorizationCode code = response.toSuccessResponse().getAuthorizationCode();

      System.out.println(response.toSuccessResponse());

      final URI callback = new URI("http://localhost:1337/cb");
      final AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, callback);

      final ClientID clientID = new ClientID(this.clientConfiguration.getClientId());
      final Secret clientSecret = new Secret(this.clientConfiguration.getClientSecret());
      final ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

      final URI tokenEndpoint = new URI(this.clientConfiguration.getTokenEndpoint());

      final TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);
      final SSLContext ctx = SSLContext.getInstance("TLS");
      ctx.init(null, new TrustManager[]{new NoTrust()}, null);

      final HTTPRequest httpRequest = request.toHTTPRequest();
      httpRequest.setSSLSocketFactory(ctx.getSocketFactory());
      httpRequest.setHostnameVerifier(new NoopHostnameVerifier());
      final HTTPResponse send = httpRequest.send();
      final TokenResponse tokenResponse = OIDCTokenResponseParser.parse(send);

      if (!response.indicatesSuccess()) {
        // We got an error response...
        final TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
      }

      final OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

      final JWT idToken = successResponse.getOIDCTokens().getIDToken();
      final AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();

      final UserInfoRequest userInfoRequest =
          new UserInfoRequest(URI.create(this.clientConfiguration.getUserInfoEndpoint()), accessToken);

      final HTTPRequest userInfoRequestHTTPRequest = userInfoRequest.toHTTPRequest();
      userInfoRequestHTTPRequest
          .setSSLSocketFactory(ctx.getSocketFactory());
      userInfoRequestHTTPRequest.setHostnameVerifier(new NoopHostnameVerifier());

      final HTTPResponse userInfoResponse = userInfoRequestHTTPRequest.send();
      final UserInfoResponse parsedUserInfo = UserInfoResponse.parse(userInfoResponse);

      String jsonString = "";

      if (parsedUserInfo.indicatesSuccess()) {
        jsonString = parsedUserInfo.toSuccessResponse().getUserInfo().toJSONString();
      } else {
        jsonString = parsedUserInfo.toErrorResponse().getErrorObject().toJSONObject().toString();
      }

      final String payload = """
          accessToken:
          %s
                    
          idToken:
          %s
                    
          userInfo:
          %s
                    
          """.formatted(
          this.prettyPrint(SignedJWT.parse(accessToken.getValue()).getJWTClaimsSet().toString(false)),
          this.prettyPrint(idToken.getJWTClaimsSet().toString(false)),
          this.prettyPrint(jsonString)
      );

      exchange.sendResponseHeaders(200, payload.length());
      exchange.getResponseBody().write(payload.getBytes(StandardCharsets.UTF_8));
    } catch (final Exception e) {
      exchange.sendResponseHeaders(500, e.getMessage().length());
      exchange.getResponseBody().write(e.getMessage().getBytes(StandardCharsets.UTF_8));
      throw new RuntimeException(e);
    } finally {
      this.server.stop(0);
    }
  }
}
