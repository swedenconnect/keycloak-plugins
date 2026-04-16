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
import java.nio.charset.StandardCharsets;

/**
 * JAX-RS {@link ContainerRequestFilter} that normalizes duplicate {@code resource} form
 * parameters in OAuth 2.0 token (POST) requests to support RFC 8707.
 *
 * <p>Runs post-match (no {@code @PreMatching}) so it executes on a worker thread — Keycloak's
 * token endpoint is blocking, and RESTEasy Reactive dispatches the entire post-match filter
 * chain to the worker pool when the matched resource is blocking. This makes blocking body reads
 * safe here. {@code setRequestUri()} is not needed for POST, so {@code @PreMatching} is not
 * required (and would conflict with the IO-thread constraint).
 *
 * <p>Multiple {@code resource=} values in the form body are collapsed to a single comma-joined
 * value before Keycloak parses the body and runs its duplicate-parameter check.
 * {@link se.swedenconnect.keycloak.oidc.Rfc8707TokenEndpointExecutor} splits the value back out.
 *
 * <p>GET query-string normalization for the authorization endpoint is handled by the companion
 * {@link Rfc8707ContainerRequestFilter}.
 *
 * @author Felix Hellman
 */
@Provider
public class Rfc8707PostBodyFilter implements ContainerRequestFilter {

  private static final Logger log = Logger.getLogger(Rfc8707PostBodyFilter.class);

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
    final String normalized = Rfc8707ContainerRequestFilter.normalizeFormBody(body);
    if (!body.equals(normalized)) {
      log.debugf("RFC 8707: collapsed duplicate resource parameters in form body");
    }
    requestContext.setEntityStream(new ByteArrayInputStream(normalized.getBytes(StandardCharsets.UTF_8)));
  }
}
