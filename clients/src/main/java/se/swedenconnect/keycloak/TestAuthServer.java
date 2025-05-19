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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TestAuthServer {
  public static final ObjectMapper MAPPER = new ObjectMapper();
  private final AtomicBoolean active = new AtomicBoolean(false);
  private final JWK signKey = generateKey();
  private final HttpServer server;
  private final Map<String, String> codeToNonceMap = new HashMap<>();
  private final List<Consumer<JWTClaimsSet.Builder>> accessTokenCustomizers = new ArrayList<>();
  private final List<Consumer<JWTClaimsSet.Builder>> idTokenCustomizers = new ArrayList<>();
  private final List<Consumer<JWTClaimsSet.Builder>> userInfoCustomizers = new ArrayList<>();
  private final Integer port;

  private static final Pattern QUERY_REGEX = Pattern.compile("^(?<key>[a-z_-]*)=(?<value>.*)$");


  public TestAuthServer() throws Exception {
    this.port = 60000 + new Random().nextInt(2000);
    this.server = HttpServer.create(new InetSocketAddress(this.port), 0);
  }

  public void start() throws Exception {
    server.createContext("/auth", exchange -> {
      final String[] split = exchange.getRequestURI().getQuery().split("&");
      final Map<String, String> queryParams = new HashMap<>();
      Arrays.stream(split)
          .forEach(param -> {
            final Matcher matcher = QUERY_REGEX.matcher(param);
            if (matcher.matches()) {
              queryParams.put(matcher.group("key"), matcher.group("value"));
            }
          });

      final String code = UUID.randomUUID().toString();
      this.codeToNonceMap.put(code, queryParams.get("nonce"));

      final String redirect = queryParams.get("redirect_uri") + "?code=%s&state=%s".formatted(
          code,
          queryParams.get("state")
      );
      exchange.getResponseHeaders().add("Location", redirect);
      exchange.sendResponseHeaders(302, 0);
    });
    server.createContext("/token", exchange -> {

      final String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      final String[] split = body.split("&");
      final Map<String, String> request = new HashMap<>();

      Arrays.stream(split)
          .forEach(param -> {
            final Matcher matcher = QUERY_REGEX.matcher(param);
            if (matcher.matches()) {
              request.put(matcher.group("key"), matcher.group("value"));
            }
          });

      try {
        final JWTClaimsSet.Builder accessTokenBuilder = new JWTClaimsSet.Builder()
            .expirationTime(Date.from(Instant.now().plus(60, ChronoUnit.MINUTES)))
            .issueTime(Date.from(Instant.now()))
            .audience(request.get("client_id"))
            .issuer("http://host.docker.internal:%d".formatted(this.port))
            .claim("nonce", this.codeToNonceMap.get((String) request.get("code")));

        accessTokenCustomizers.forEach(customizer -> {
          customizer.accept(accessTokenBuilder);
        });

        final JWTClaimsSet.Builder idTokenBuilder = new JWTClaimsSet.Builder()
            .expirationTime(Date.from(Instant.now().plus(60, ChronoUnit.MINUTES)))
            .issueTime(Date.from(Instant.now()))
            .audience(request.get("client_id"))
            .subject(UUID.randomUUID().toString())
            .claim("name", "First Last")
            .claim("given_name", "First")
            .claim("family_name", "Last")
            .claim("preferred_username", "username")
            .claim("nonce", this.codeToNonceMap.get((String) request.get("code")))
            .issuer("http://host.docker.internal:%d".formatted(this.port));

        idTokenCustomizers.forEach(customizer -> {
          customizer.accept(idTokenBuilder);
        });

        final JWSSigner signer = this.getSigner(this.signKey);

        final SignedJWT accessToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), accessTokenBuilder.build());
        final SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), idTokenBuilder.build());

        accessToken.sign(signer);
        idToken.sign(signer);

        final Map<String, String> response = Map.of(
            "access_token", accessToken.serialize(),
            "id_token", idToken.serialize(),
            "expires_in", "3600",
            "token_type", "Bearer"
        );

        final String payload = MAPPER.writerFor(Map.class).writeValueAsString(response);

        exchange.sendResponseHeaders(200, payload.length());
        exchange.getResponseBody().write(payload.getBytes(StandardCharsets.UTF_8));
      } catch (final Exception e) {
        System.out.println(e.getMessage());
      }
    });
    server.createContext("/certs", exchange -> {
      final Map<String, Object> keys = new JWKSet(this.signKey)
          .toPublicJWKSet()
          .toJSONObject();

      final String payload = MAPPER.writerFor(Map.class).writeValueAsString(keys);

      exchange.sendResponseHeaders(200, payload.length());
      exchange.getResponseBody().write(payload.getBytes(StandardCharsets.UTF_8));
    });
    server.createContext("/userinfox", exchange -> {
      try {
        System.out.println("USERINFO REQUEST");
        final JWTClaimsSet.Builder userInfoBuilder = new JWTClaimsSet.Builder()
            .expirationTime(Date.from(Instant.now().plus(60, ChronoUnit.MINUTES)))
            .issueTime(Date.from(Instant.now()))
            .issuer("http://host.docker.internal:1338");

        userInfoCustomizers.forEach(customizer -> {
          customizer.accept(userInfoBuilder);
        });

        final String payload = MAPPER.writerFor(Map.class).writeValueAsString(userInfoBuilder.build().getClaims());

        exchange.sendResponseHeaders(200, payload.length());
        exchange.getResponseBody().write(payload.getBytes(StandardCharsets.UTF_8));
      } catch (final Exception e) {
        System.out.println(e.getMessage());
        exchange.sendResponseHeaders(500, e.getMessage().length());
        exchange.getResponseBody().write(e.getMessage().getBytes(StandardCharsets.UTF_8));
      }
    });

    this.server.setExecutor(Executors.newFixedThreadPool(10));
    this.active.set(true);
    this.server.start();
  }

  private static RSAKey generateKey() throws JOSEException {
    return new RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(new Date())
        .generate();
  }

  private JWSSigner getSigner(final JWK signingKey) throws JOSEException {
    final KeyType keyType = signingKey.getKeyType();
    if (keyType.equals(KeyType.EC)) {
      return new ECDSASigner(signingKey.toECKey());
    }
    if (keyType.equals(KeyType.RSA)) {
      return new RSASSASigner(signingKey.toRSAKey());
    }
    throw new JOSEException("Unsupported key type");
  }

  public TestAuthServer withIdTokenCustomizer(final Consumer<JWTClaimsSet.Builder> customizer) {
    this.idTokenCustomizers.add(customizer);
    return this;
  }

  public TestAuthServer withAccessTokenCustomizer(final Consumer<JWTClaimsSet.Builder> customizer) {
    this.accessTokenCustomizers.add(customizer);
    return this;
  }

  public TestAuthServer withUserInfoCustomizer(final Consumer<JWTClaimsSet.Builder> customizer) {
    this.userInfoCustomizers.add(customizer);
    return this;
  }

  public Integer getPort() {
    return port;
  }
}
