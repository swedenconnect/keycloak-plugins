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
package se.swedenconnect.keycloak.servlet;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JAX-RS {@link ContainerRequestFilter} that normalizes duplicate {@code resource} parameters
 * in OAuth 2.0 requests to support RFC 8707 (Resource Indicators for OAuth 2.0).
 *
 * <p>Keycloak 26 rejects any form parameter that appears more than once with
 * {@code invalid_request: duplicated parameter}. This filter intercepts form-encoded POST
 * requests before Keycloak parses the body and collapses multiple {@code resource=} values
 * into a single comma-joined value. Any other duplicated parameters are reduced to their
 * first value. {@link se.swedenconnect.keycloak.oidc.Rfc8707TokenEndpointExecutor} splits
 * the comma-joined resource value back out during token processing.
 *
 * <p>Registered as a JAX-RS {@code @Provider}. Keycloak 26 discovers it from the provider
 * JAR during {@code kc.sh build} (or at startup in dev mode).
 *
 * @author Felix Hellman
 */
@Provider
public class Rfc8707ContainerRequestFilter implements ContainerRequestFilter {

  private static final Logger log = Logger.getLogger(Rfc8707ContainerRequestFilter.class);

  static final String RESOURCE_PARAM = "resource";

  @Override
  public void filter(final ContainerRequestContext requestContext) throws IOException {
    if (!"POST".equalsIgnoreCase(requestContext.getMethod())) {
      return;
    }
    final MediaType contentType = requestContext.getMediaType();
    if (contentType == null || !contentType.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE)) {
      return;
    }
    if (requestContext.getEntityStream() == null) {
      return;
    }

    final byte[] bodyBytes = requestContext.getEntityStream().readAllBytes();
    if (bodyBytes.length == 0) {
      return;
    }

    final String body = new String(bodyBytes, StandardCharsets.UTF_8);
    final String normalized = normalizeFormBody(body);

    if (!body.equals(normalized)) {
      log.debugf("RFC 8707: collapsed duplicate resource parameters in form body");
    }

    requestContext.setEntityStream(new ByteArrayInputStream(normalized.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Normalizes a {@code application/x-www-form-urlencoded} body:
   * <ul>
   *   <li>Multiple {@code resource=} entries are collapsed to one comma-joined value.</li>
   *   <li>Any other duplicate parameter is reduced to its first occurrence.</li>
   * </ul>
   *
   * @param body the raw form body
   * @return normalized form body
   */
  static String normalizeFormBody(final String body) {
    if (body == null || body.isEmpty()) {
      return body;
    }

    final List<String> resourceValues = new ArrayList<>();
    final Map<String, String> otherParams = new LinkedHashMap<>();
    final List<String> paramOrder = new ArrayList<>();

    for (final String pair : body.split("&")) {
      final int eq = pair.indexOf('=');
      if (eq < 0) {
        continue;
      }
      final String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
      final String value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);

      if (RESOURCE_PARAM.equals(key)) {
        resourceValues.add(value);
        if (!paramOrder.contains(RESOURCE_PARAM)) {
          paramOrder.add(RESOURCE_PARAM);
        }
      } else if (!otherParams.containsKey(key)) {
        otherParams.put(key, value);
        paramOrder.add(key);
      }
    }

    final StringBuilder sb = new StringBuilder();
    for (final String key : paramOrder) {
      if (!sb.isEmpty()) {
        sb.append('&');
      }
      sb.append(URLEncoder.encode(key, StandardCharsets.UTF_8)).append('=');
      if (RESOURCE_PARAM.equals(key)) {
        sb.append(URLEncoder.encode(String.join(",", resourceValues), StandardCharsets.UTF_8));
      } else {
        sb.append(URLEncoder.encode(otherParams.get(key), StandardCharsets.UTF_8));
      }
    }
    return sb.toString();
  }
}
