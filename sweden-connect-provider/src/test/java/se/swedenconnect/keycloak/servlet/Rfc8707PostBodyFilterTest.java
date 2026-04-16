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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

class Rfc8707PostBodyFilterTest {

  @Test
  void filterReplacesEntityStreamWithNormalizedBody() throws Exception {
    final String body = "grant_type=refresh_token"
        + "&resource=https%3A%2F%2Fapi1.example.com"
        + "&resource=https%3A%2F%2Fapi2.example.com";

    final ContainerRequestContext ctx = mockPostContext(body);
    final ArgumentCaptor<InputStream> captor = ArgumentCaptor.forClass(InputStream.class);

    new Rfc8707PostBodyFilter().filter(ctx);

    Mockito.verify(ctx).setEntityStream(captor.capture());
    final String result = new String(captor.getValue().readAllBytes(), StandardCharsets.UTF_8);
    Assertions.assertEquals(1, countOccurrences(result, "resource="),
        "normalized body must have single resource= entry");
    Assertions.assertTrue(result.contains("grant_type=refresh_token"), "other params preserved");
  }

  @Test
  void filterSkipsNonFormContentType() throws Exception {
    final ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
    Mockito.when(ctx.getMethod()).thenReturn("POST");
    Mockito.when(ctx.getMediaType()).thenReturn(MediaType.APPLICATION_JSON_TYPE);

    new Rfc8707PostBodyFilter().filter(ctx);

    Mockito.verify(ctx, Mockito.never()).setEntityStream(Mockito.any());
  }

  @Test
  void filterSkipsGetRequests() throws Exception {
    final ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
    Mockito.when(ctx.getMethod()).thenReturn("GET");

    new Rfc8707PostBodyFilter().filter(ctx);

    Mockito.verify(ctx, Mockito.never()).setEntityStream(Mockito.any());
  }

  @Test
  void filterSkipsEmptyBody() throws Exception {
    final ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
    Mockito.when(ctx.getMethod()).thenReturn("POST");
    Mockito.when(ctx.getMediaType()).thenReturn(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    Mockito.when(ctx.getEntityStream())
        .thenReturn(new ByteArrayInputStream(new byte[0]));

    new Rfc8707PostBodyFilter().filter(ctx);

    Mockito.verify(ctx, Mockito.never()).setEntityStream(Mockito.any());
  }

  private static ContainerRequestContext mockPostContext(final String body) {
    final ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
    Mockito.when(ctx.getMethod()).thenReturn("POST");
    Mockito.when(ctx.getMediaType()).thenReturn(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    Mockito.when(ctx.getEntityStream())
        .thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
    return ctx;
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
