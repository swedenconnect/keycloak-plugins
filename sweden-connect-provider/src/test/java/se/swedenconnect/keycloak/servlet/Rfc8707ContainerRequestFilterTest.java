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
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.net.URI;

class Rfc8707ContainerRequestFilterTest {

  // --- normalizeFormBody unit tests ---

  @Test
  void multipleResourceValuesAreCollapsedToCommaJoined() {
    final String body = "grant_type=refresh_token&resource=https%3A%2F%2Fapi1.example.com&resource=https%3A%2F%2Fapi2.example.com";
    final String normalized = Rfc8707ContainerRequestFilter.normalizeFormBody(body);

    Assertions.assertTrue(normalized.contains("resource="),
        "resource param must be present");
    // single occurrence only
    Assertions.assertEquals(1,
        countOccurrences(normalized, "resource="),
        "resource= must appear exactly once after normalization");
    // both URIs present, comma-joined (URL-encoded)
    Assertions.assertTrue(
        normalized.contains("https%3A%2F%2Fapi1.example.com%2Chttps%3A%2F%2Fapi2.example.com")
            || normalized.contains("https://api1.example.com,https://api2.example.com"),
        "both resource URIs must be present, comma-joined");
  }

  @Test
  void singleResourceValueIsUnchanged() {
    final String body = "grant_type=authorization_code&code=ABC&resource=https%3A%2F%2Fapi.example.com";
    final String normalized = Rfc8707ContainerRequestFilter.normalizeFormBody(body);

    Assertions.assertEquals(1, countOccurrences(normalized, "resource="));
    Assertions.assertTrue(normalized.contains("grant_type=") && normalized.contains("code="));
  }

  @Test
  void duplicateNonResourceParamsReducedToFirst() {
    final String body = "grant_type=refresh_token&grant_type=authorization_code&client_id=my-client";
    final String normalized = Rfc8707ContainerRequestFilter.normalizeFormBody(body);

    Assertions.assertEquals(1, countOccurrences(normalized, "grant_type="),
        "duplicate grant_type must be reduced to one");
    Assertions.assertTrue(normalized.contains("grant_type=refresh_token"),
        "first grant_type value must be kept");
  }

  @Test
  void noResourceParamPassesThrough() {
    final String body = "grant_type=client_credentials&client_id=foo&client_secret=bar";
    final String normalized = Rfc8707ContainerRequestFilter.normalizeFormBody(body);

    Assertions.assertFalse(normalized.contains("resource="));
    Assertions.assertTrue(normalized.contains("grant_type=client_credentials"));
  }

  @Test
  void emptyBodyReturnsEmpty() {
    Assertions.assertEquals("", Rfc8707ContainerRequestFilter.normalizeFormBody(""));
    Assertions.assertNull(Rfc8707ContainerRequestFilter.normalizeFormBody(null));
  }

  // --- GET filter() integration tests ---

  @Test
  void filterNormalizesQueryStringForGet() throws Exception {
    final URI original = URI.create("https://kc.example.com/realms/test/protocol/openid-connect/auth"
        + "?response_type=code&client_id=my-client"
        + "&resource=https%3A%2F%2Fapi1.example.com&resource=https%3A%2F%2Fapi2.example.com"
        + "&scope=openid+read");

    final UriInfo uriInfo = Mockito.mock(UriInfo.class);
    Mockito.when(uriInfo.getRequestUri()).thenReturn(original);

    final ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
    Mockito.when(ctx.getMethod()).thenReturn("GET");
    Mockito.when(ctx.getUriInfo()).thenReturn(uriInfo);

    final ArgumentCaptor<URI> captor = ArgumentCaptor.forClass(URI.class);
    new Rfc8707ContainerRequestFilter().filter(ctx);

    Mockito.verify(ctx).setRequestUri(captor.capture());
    final String query = captor.getValue().getRawQuery();
    Assertions.assertEquals(1, countOccurrences(query, "resource="),
        "normalized query must have single resource= entry");
    Assertions.assertTrue(query.contains("response_type=code"), "other params preserved");
  }

  @Test
  void filterSkipsGetWithSingleResource() throws Exception {
    final URI original = URI.create("https://kc.example.com/auth?response_type=code&resource=https%3A%2F%2Fapi.example.com");

    final UriInfo uriInfo = Mockito.mock(UriInfo.class);
    Mockito.when(uriInfo.getRequestUri()).thenReturn(original);

    final ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
    Mockito.when(ctx.getMethod()).thenReturn("GET");
    Mockito.when(ctx.getUriInfo()).thenReturn(uriInfo);

    new Rfc8707ContainerRequestFilter().filter(ctx);

    // single resource — URI unchanged, setRequestUri never called
    Mockito.verify(ctx, Mockito.never()).setRequestUri(Mockito.any());
  }

  @Test
  void filterSkipsPostRequests() throws Exception {
    final ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
    Mockito.when(ctx.getMethod()).thenReturn("POST");

    new Rfc8707ContainerRequestFilter().filter(ctx);

    Mockito.verify(ctx, Mockito.never()).setRequestUri(Mockito.any());
    Mockito.verify(ctx, Mockito.never()).setEntityStream(Mockito.any());
  }

  private static int countOccurrences(final String text, final String sub) {
    int count = 0;
    int idx = 0;
    while ((idx = text.indexOf(sub, idx)) != -1) {
      count++;
      idx += sub.length();
    }
    return count;
  }
}
