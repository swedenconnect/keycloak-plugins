/*
 * Copyright 2026 Sweden Connect
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
package se.swedenconnect.keycloak.it;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.CookieHandler;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A minimal scripted browser for driving Keycloak login pages: keeps cookies, follows redirects,
 * parses HTML forms and links. No JavaScript, so the auto-submitting SAML forms are posted by hand.
 *
 * <p>Uses its own cookie jar instead of {@link java.net.CookieManager}. The JDK jar refuses to
 * return cookies flagged {@code Secure} over plain HTTP, and it has awkward domain matching for
 * dot-less hosts such as {@code localhost}; both would silently drop Keycloak's
 * {@code AUTH_SESSION_ID} / {@code KC_RESTART} cookies and fail the login with
 * "Restart login cookie not found". Cookies are matched on path only, which is enough since the
 * whole test talks to a single host.
 *
 * @author David Goldring
 */
final class Browser {

  /** A fetched page. {@code uri} is where the browser ended up after redirects. */
  record Page(int status, URI uri, String body, HttpHeaders headers) {

    Optional<String> location() {
      return this.headers.firstValue("location");
    }
  }

  /** An HTML form: its (unescaped) action URL and every named input with its current value. */
  record Form(String action, Map<String, String> fields) {

    boolean has(final String field) {
      return this.fields.containsKey(field);
    }
  }

  private static final Pattern FORM = Pattern.compile("<form([^>]*)>(.*?)</form>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
  private static final Pattern INPUT = Pattern.compile("<input[^>]*>", Pattern.CASE_INSENSITIVE);
  private static final Pattern ATTRIBUTE = Pattern.compile("([\\w-]+)=\"([^\"]*)\"");
  private static final Pattern HREF = Pattern.compile("href=\"([^\"]*)\"");
  private static final Pattern ENTITY = Pattern.compile("&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);");

  private final HttpClient following;
  private final HttpClient direct;

  Browser() {
    final CookieJar cookies = new CookieJar();
    this.following = HttpClient.newBuilder()
        .cookieHandler(cookies)
        .followRedirects(HttpClient.Redirect.NORMAL)
        .proxy(HttpClient.Builder.NO_PROXY)
        .connectTimeout(Duration.ofSeconds(30))
        .build();
    this.direct = HttpClient.newBuilder()
        .cookieHandler(cookies)
        .followRedirects(HttpClient.Redirect.NEVER)
        .proxy(HttpClient.Builder.NO_PROXY)
        .connectTimeout(Duration.ofSeconds(30))
        .build();
  }

  /** GET, following redirects. */
  Page get(final String url) {
    return this.send(this.following, HttpRequest.newBuilder(URI.create(url)).GET());
  }

  /** GET with a bearer token, following redirects. */
  Page getWithBearer(final String url, final String accessToken) {
    return this.send(this.following, HttpRequest.newBuilder(URI.create(url))
        .header("Authorization", "Bearer " + accessToken)
        .GET());
  }

  /** GET without following redirects, so that the {@code Location} header can be inspected. */
  Page getWithoutRedirect(final String url) {
    return this.send(this.direct, HttpRequest.newBuilder(URI.create(url)).GET());
  }

  /** POST a form, following redirects (a 302 after POST is re-issued as a GET, as browsers do). */
  Page postForm(final String url, final Map<String, String> fields) {
    return this.send(this.following, HttpRequest.newBuilder(URI.create(url))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(encode(fields))));
  }

  /** POST a form without following redirects. */
  Page postFormWithoutRedirect(final String url, final Map<String, String> fields) {
    return this.send(this.direct, HttpRequest.newBuilder(URI.create(url))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(encode(fields))));
  }

  /** Submit a parsed form with some of its fields overridden or added. */
  Page submit(final Form form, final Map<String, String> overrides) {
    final Map<String, String> fields = new LinkedHashMap<>(form.fields());
    fields.putAll(overrides);
    return this.postForm(form.action(), fields);
  }

  private Page send(final HttpClient client, final HttpRequest.Builder request) {
    try {
      final HttpResponse<String> response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
      return new Page(response.statusCode(), response.uri(), response.body(), response.headers());
    }
    catch (final IOException e) {
      throw new UncheckedIOException(e);
    }
    catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Interrupted while waiting for " + request.build().uri(), e);
    }
  }

  /** Every {@code <form>} on the page, in document order. */
  static List<Form> forms(final String html) {
    final List<Form> forms = new ArrayList<>();
    final Matcher form = FORM.matcher(html);
    while (form.find()) {
      final String action = attributes(form.group(1)).getOrDefault("action", "");
      final Map<String, String> fields = new LinkedHashMap<>();
      final Matcher input = INPUT.matcher(form.group(2));
      while (input.find()) {
        final Map<String, String> attributes = attributes(input.group());
        final String name = attributes.get("name");
        if (Objects.nonNull(name)) {
          fields.put(name, unescape(attributes.getOrDefault("value", "")));
        }
      }
      forms.add(new Form(unescape(action), fields));
    }
    return forms;
  }

  /** The first form on the page that carries the given field. */
  static Optional<Form> formWith(final String html, final String field) {
    return forms(html).stream().filter(form -> form.has(field)).findFirst();
  }

  /** The first form on the page whose action contains the given text. */
  static Optional<Form> formPostingTo(final String html, final String actionFragment) {
    return forms(html).stream().filter(form -> form.action().contains(actionFragment)).findFirst();
  }

  /** The first (unescaped) {@code href} on the page that contains the given text. */
  static Optional<String> link(final String html, final String hrefFragment) {
    final Matcher href = HREF.matcher(html);
    while (href.find()) {
      final String url = unescape(href.group(1));
      if (url.contains(hrefFragment)) {
        return Optional.of(url);
      }
    }
    return Optional.empty();
  }

  /** The query parameters of a URL, decoded. */
  static Map<String, String> queryParameters(final String url) {
    final String query = URI.create(url).getRawQuery();
    if (Objects.isNull(query) || query.isBlank()) {
      return Map.of();
    }
    final Map<String, String> parameters = new LinkedHashMap<>();
    for (final String pair : query.split("&")) {
      final int eq = pair.indexOf('=');
      final String key = eq < 0 ? pair : pair.substring(0, eq);
      final String value = eq < 0 ? "" : pair.substring(eq + 1);
      parameters.put(URLDecoder.decode(key, StandardCharsets.UTF_8), URLDecoder.decode(value, StandardCharsets.UTF_8));
    }
    return parameters;
  }

  static String encode(final Map<String, String> fields) {
    return fields.entrySet().stream()
        .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)
            + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .collect(Collectors.joining("&"));
  }

  private static Map<String, String> attributes(final String tag) {
    final Map<String, String> attributes = new LinkedHashMap<>();
    final Matcher attribute = ATTRIBUTE.matcher(tag);
    while (attribute.find()) {
      attributes.put(attribute.group(1).toLowerCase(), attribute.group(2));
    }
    return attributes;
  }

  /** Unescapes the entities Keycloak's templates emit in attribute values. */
  static String unescape(final String text) {
    final Matcher entity = ENTITY.matcher(text);
    final StringBuilder out = new StringBuilder();
    while (entity.find()) {
      final String name = entity.group(1);
      final String replacement = switch (name) {
        case "amp" -> "&";
        case "lt" -> "<";
        case "gt" -> ">";
        case "quot" -> "\"";
        case "apos" -> "'";
        default -> name.startsWith("#x")
            ? Character.toString(Integer.parseInt(name.substring(2), 16))
            : Character.toString(Integer.parseInt(name.substring(1)));
      };
      entity.appendReplacement(out, Matcher.quoteReplacement(replacement));
    }
    entity.appendTail(out);
    return out.toString();
  }

  /**
   * Path-scoped cookie jar for a single host. Ignores the {@code Secure} and {@code Domain}
   * attributes, see the class comment.
   */
  private static final class CookieJar extends CookieHandler {

    private final Map<String, HttpCookie> jar = new LinkedHashMap<>();

    @Override
    public synchronized Map<String, List<String>> get(final URI uri, final Map<String, List<String>> requestHeaders) {
      final String requestPath = Objects.requireNonNullElse(uri.getPath(), "/");
      final String header = this.jar.values().stream()
          .filter(cookie -> pathMatches(requestPath, cookie.getPath()))
          .map(cookie -> cookie.getName() + "=" + cookie.getValue())
          .collect(Collectors.joining("; "));
      return header.isEmpty() ? Map.of() : Map.of("Cookie", List.of(header));
    }

    @Override
    public synchronized void put(final URI uri, final Map<String, List<String>> responseHeaders) {
      responseHeaders.forEach((name, values) -> {
        if ("set-cookie".equalsIgnoreCase(name)) {
          values.forEach(value -> HttpCookie.parse(value).forEach(cookie -> this.store(uri, cookie)));
        }
      });
    }

    private void store(final URI uri, final HttpCookie cookie) {
      final String path = Objects.requireNonNullElseGet(cookie.getPath(), () -> defaultPath(uri));
      cookie.setPath(path);
      final String key = cookie.getName() + "@" + path;
      if (cookie.hasExpired() || cookie.getMaxAge() == 0) {
        this.jar.remove(key);
      }
      else {
        this.jar.put(key, cookie);
      }
    }

    /** RFC 6265 section 5.1.4: the request path minus everything after its last slash. */
    private static String defaultPath(final URI uri) {
      final String path = Objects.requireNonNullElse(uri.getPath(), "/");
      final int lastSlash = path.lastIndexOf('/');
      return lastSlash <= 0 ? "/" : path.substring(0, lastSlash);
    }

    /** RFC 6265 section 5.1.4 path-match. */
    private static boolean pathMatches(final String requestPath, final String cookiePath) {
      if (requestPath.equals(cookiePath)) {
        return true;
      }
      if (!requestPath.startsWith(cookiePath)) {
        return false;
      }
      return cookiePath.endsWith("/") || requestPath.charAt(cookiePath.length()) == '/';
    }
  }
}
