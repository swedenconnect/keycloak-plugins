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
package se.swedenconnect.keycloak.oidc;

import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenCategory;
import org.keycloak.crypto.HashProvider;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.AudienceProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenResponseMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Resource indicators (RFC 8707) and audience for standard token exchange (RFC 8693), following section 2.3 of the Ena
 * chaining profile: a target ({@code resource} or {@code audience}) identifying the downstream protected resource is
 * enough, and the scopes of the issued token are the ones relevant to that resource.
 *
 * <p>Keycloak 26.8 accepts {@code resource} in a token exchange request but ignores it, and it only puts an audience in
 * {@code aud} if a requested (or default) scope of the exchanging client has an audience mapper for it. So
 * {@code resource} or {@code audience} without the matching {@code scope} fails. This mapper fills both gaps.</p>
 *
 * <ul>
 *   <li>Only token exchange requests are affected. Targets are only handled when the request has {@code resource} or
 *   {@code audience}; permission scopes (below) always.</li>
 *   <li>{@code resource} and {@code audience} are read from the POST body and from the query string. Several values
 *   are allowed (repeated, or separated by commas: {@link se.swedenconnect.keycloak.servlet.Rfc8707PostBodyFilter}
 *   joins repeated resource values with commas); duplicates are ignored.</li>
 *   <li>Target to scope: for each target, the mapper looks for an audience mapper with that audience (client audience
 *   or custom audience) among the exchanging client's own mappers and its default and optional client scopes. Such a
 *   scope is taken as the client's entitlement to the target (Ena 2.3.1). The target is added to {@code aud}, and the
 *   scope to the token's {@code scope} claim, even if the request did not ask for the scope. Only the audience mapper
 *   of a scope found this way is applied: Keycloak did not add the scope to the session.</li>
 *   <li>Scopes that only give audiences other than the targets are removed from the {@code scope} claim (Ena 2.4).
 *   Scopes without an audience mapper are kept. The {@code scope} field of the token response JSON cannot be changed:
 *   Keycloak sets it after the mappers have run. Configurable: {@value #REMOVE_OTHER_SCOPES}.</li>
 *   <li>Permission scopes (the exchanging client's client scopes without mappers, such as {@code resource:read}), in
 *   every token exchange: such a scope is only in the issued token if the request asks for it (Keycloak's own rule)
 *   and the subject token has it (Ena 2.3.1, no upscoping). Configurable: {@value #REQUIRE_SUBJECT_TOKEN_SCOPES}.</li>
 *   <li>{@code aud} then becomes exactly the requested resources ({@code audience} narrows {@code aud} through
 *   Keycloak itself).</li>
 *   <li>A resource that no scope gives, or that drops out because {@code resource} and {@code audience} name different
 *   resources, means no token: the response has {@code error=invalid_target} and no {@code access_token}. A protocol
 *   mapper cannot change the HTTP status, so the status is still 200.</li>
 * </ul>
 *
 * <p>Phases: this mapper has priority {@value ProtocolMapperUtils#PRIORITY_SCRIPT_MAPPER} and audience mappers 0, so
 * the access token phase runs after the audience mappers, and before Keycloak checks {@code audience}. Keycloak narrows
 * {@code aud} to {@code audience} after all mappers have run, so the narrowing to the resources happens in the token
 * response phase, which sees the final access token. It narrows {@code aud} and signs the access token again, and the
 * ID token (if any) too, with {@code at_hash} for the new access token. The mapper must therefore be included in the
 * access token, the ID token and the token response. It sets no claim of its own.</p>
 *
 * @author Sweden Connect
 */
public class TokenExchangeTargetMapper extends AbstractOIDCProtocolMapper
    implements OIDCAccessTokenMapper, OIDCIDTokenMapper, OIDCAccessTokenResponseMapper {

  /** The mapper type. */
  public static final String PROVIDER_ID = "oidc-token-exchange-target-mapper";

  /** Config: remove scopes that only give audiences other than the targets (default true). */
  public static final String REMOVE_OTHER_SCOPES = "remove.other.resource.scopes";

  /** Config: permission scopes must be in the subject token (default true). */
  public static final String REQUIRE_SUBJECT_TOKEN_SCOPES = "require.subject.token.scopes";

  /** The error code of a token response for a resource that the client cannot get. */
  public static final String INVALID_TARGET = "invalid_target";

  /** KeycloakSession attribute that carries the tokens from the token phases to the token response phase. */
  static final String STATE = TokenExchangeTargetMapper.class.getName() + ".state";

  private static final Logger log = Logger.getLogger(TokenExchangeTargetMapper.class);

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

  static {
    final ProviderConfigProperty removeOther = new ProviderConfigProperty();
    removeOther.setName(REMOVE_OTHER_SCOPES);
    removeOther.setLabel("Remove scopes for other resources");
    removeOther.setHelpText("When resource or audience is requested, remove the client scopes whose audience "
        + "mappers only give other audiences from the scope claim (Ena chaining profile 2.4).");
    removeOther.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    removeOther.setDefaultValue("true");
    CONFIG_PROPERTIES.add(removeOther);

    final ProviderConfigProperty requireSubject = new ProviderConfigProperty();
    requireSubject.setName(REQUIRE_SUBJECT_TOKEN_SCOPES);
    requireSubject.setLabel("Permission scopes must be in the subject token");
    requireSubject.setHelpText("Remove client scopes without mappers (such as resource:read) from the scope claim "
        + "unless the subject token has them (Ena chaining profile 2.3.1, no upscoping).");
    requireSubject.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    requireSubject.setDefaultValue("true");
    CONFIG_PROPERTIES.add(requireSubject);

    OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, TokenExchangeTargetMapper.class);
  }

  /**
   * The audiences that the audience mappers of a client or a client scope give.
   *
   * @param scope the client scope, or {@code null} for the client's own mappers
   * @param audiences the audiences, not empty
   */
  record AudienceSource(ClientScopeModel scope, Set<String> audiences) {
  }

  /** The tokens of this request, kept for the token response phase. */
  private static final class State {
    private AccessToken access;
    private IDToken id;
  }

  /** {@inheritDoc} */
  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  /** {@inheritDoc} */
  @Override
  public String getDisplayCategory() {
    return TOKEN_MAPPER_CATEGORY;
  }

  /** {@inheritDoc} */
  @Override
  public String getDisplayType() {
    return "Token exchange resource and audience";
  }

  /** {@inheritDoc} */
  @Override
  public String getHelpText() {
    return "Token exchange (Ena chaining profile 2.3): resource or audience alone selects the downstream resource. "
        + "Adds it to aud and the client scope that gives it to scope, removes unrelated scopes, and narrows aud to "
        + "the requested resources. Include it in the access token, the ID token and the token response.";
  }

  /** {@inheritDoc} */
  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  /**
   * Runs after the audience mappers (0), like script mappers.
   *
   * @return the priority
   */
  @Override
  public int getPriority() {
    return ProtocolMapperUtils.PRIORITY_SCRIPT_MAPPER;
  }

  /** Access token and ID token phase. */
  @Override
  protected void setClaim(final IDToken token, final ProtocolMapperModel mapper, final UserSessionModel userSession,
      final KeycloakSession session, final ClientSessionContext clientSessionCtx) {
    final MultivaluedMap<String, String> form = formParameters(session);
    if (form == null || !OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE.equals(form.getFirst(OAuth2Constants.GRANT_TYPE))) {
      return;
    }
    final Set<String> resources = requestedValues(session, form, OAuth2Constants.RESOURCE);
    final Set<String> targets = new LinkedHashSet<>(resources);
    targets.addAll(requestedValues(session, form, OAuth2Constants.AUDIENCE));

    final ClientModel client = session.getContext().getClient();
    if (token instanceof final AccessToken accessToken && client != null) {
      if (!targets.isEmpty()) {
        addTargets(accessToken, audienceSources(client), targets, isEnabled(mapper, REMOVE_OTHER_SCOPES));
      }
      if (isEnabled(mapper, REQUIRE_SUBJECT_TOKEN_SCOPES)) {
        removeUnauthorizedPermissionScopes(accessToken, permissionScopes(client),
            subjectTokenScopes(form.getFirst(OAuth2Constants.SUBJECT_TOKEN)));
      }
      log.debugf("Token exchange for %s: targets %s, aud %s, scope '%s'", client.getClientId(), targets,
          accessToken.getAudience() == null ? List.of() : Arrays.asList(accessToken.getAudience()),
          accessToken.getScope());
    }
    if (resources.isEmpty()) {
      return;
    }

    State state = (State) session.getAttribute(STATE);
    if (state == null) {
      state = new State();
      session.setAttribute(STATE, state);
    }
    if (token instanceof final AccessToken accessToken) {
      state.access = accessToken;
    }
    else {
      state.id = token;
    }
  }

  /** Token response phase: narrow aud to the requested resources, and sign the tokens again. */
  @Override
  protected void setClaim(final AccessTokenResponse response, final ProtocolMapperModel mapper,
      final UserSessionModel userSession, final KeycloakSession session,
      final ClientSessionContext clientSessionCtx) {
    final State state = (State) session.getAttribute(STATE);
    if (state == null) {
      return;
    }
    session.removeAttribute(STATE);
    if (state.access == null || response.getToken() == null) {
      return;
    }

    final Set<String> requested = requestedValues(session, formParameters(session), OAuth2Constants.RESOURCE);
    final List<String> missing = missingResources(requested, state.access.getAudience());
    if (!missing.isEmpty()) {
      log.debugf("Token exchange: requested resource not available: %s", missing);
      response.setToken(null);
      response.setTokenType(null);
      response.setIdToken(null);
      response.setRefreshToken(null);
      response.setError(INVALID_TARGET);
      response.setErrorDescription("Requested resource not available: " + String.join(" ", missing));
      return;
    }

    state.access.audience(requested.toArray(String[]::new));
    final String encoded = session.tokens().encode(state.access);
    response.setToken(encoded);

    if (state.id != null && response.getIdToken() != null) {
      if (state.id.getAccessTokenHash() != null) {
        state.id.setAccessTokenHash(oidcHash(session, encoded));
      }
      response.setIdToken(session.tokens().encodeAndEncrypt(state.id));
    }
  }

  /**
   * Adds each target that a scope of the client gives to {@code aud}, adds those scopes to the scope claim, and
   * optionally removes the scopes that only give other audiences.
   *
   * @param token the access token
   * @param sources the client's audience sources
   * @param targets the requested resources and audiences
   * @param removeOtherScopes whether to remove the scopes for other resources
   */
  static void addTargets(final AccessToken token, final List<AudienceSource> sources, final Set<String> targets,
      final boolean removeOtherScopes) {
    final Set<String> relevantScopes = new LinkedHashSet<>();
    final Set<String> otherScopes = new LinkedHashSet<>();
    for (final AudienceSource source : sources) {
      boolean forTarget = false;
      for (final String audience : source.audiences()) {
        if (targets.contains(audience)) {
          forTarget = true;
          if (!token.hasAudience(audience)) {
            token.addAudience(audience);
          }
        }
      }
      if (source.scope() == null) {
        continue;
      }
      if (forTarget) {
        if (source.scope().isIncludeInTokenScope()) {
          relevantScopes.add(source.scope().getName());
        }
      }
      else {
        otherScopes.add(source.scope().getName());
      }
    }

    final Set<String> scopes = new LinkedHashSet<>(scopes(token.getScope()));
    if (removeOtherScopes) {
      scopes.removeAll(otherScopes);
    }
    scopes.addAll(relevantScopes);
    token.setScope(String.join(" ", scopes));
  }

  /**
   * Removes the permission scopes that the subject token does not have from the scope claim.
   *
   * @param token the access token
   * @param permissionScopes the client's permission scopes
   * @param subjectScopes the scopes of the subject token, or {@code null} if unknown (nothing is removed)
   */
  static void removeUnauthorizedPermissionScopes(final AccessToken token, final Set<String> permissionScopes,
      final List<String> subjectScopes) {
    if (subjectScopes == null || permissionScopes.isEmpty()) {
      return;
    }
    token.setScope(String.join(" ", scopes(token.getScope()).stream()
        .filter(s -> !permissionScopes.contains(s) || subjectScopes.contains(s))
        .toList()));
  }

  /**
   * The requested resources that are not in the audience.
   *
   * @param requested the requested resources
   * @param audience the token's audience, may be {@code null}
   * @return the missing resources
   */
  static List<String> missingResources(final Set<String> requested, final String[] audience) {
    final List<String> aud = audience == null ? List.of() : Arrays.asList(audience);
    return requested.stream().filter(r -> !aud.contains(r)).toList();
  }

  /**
   * The client's audience sources: its own audience mappers, and those of its default and optional client scopes.
   *
   * @param client the exchanging client
   * @return the sources that give at least one audience
   */
  static List<AudienceSource> audienceSources(final ClientModel client) {
    final List<AudienceSource> sources = new ArrayList<>();
    addSource(sources, null, client.getProtocolMappersStream());
    for (final boolean defaultScopes : new boolean[] { true, false }) {
      client.getClientScopes(defaultScopes).values()
          .forEach(scope -> addSource(sources, scope, scope.getProtocolMappersStream()));
    }
    return sources;
  }

  private static void addSource(final List<AudienceSource> sources, final ClientScopeModel scope,
      final Stream<ProtocolMapperModel> mappers) {
    final Set<String> audiences = new LinkedHashSet<>();
    mappers.forEach(m -> audiences.addAll(mapperAudiences(m)));
    if (!audiences.isEmpty()) {
      sources.add(new AudienceSource(scope, audiences));
    }
  }

  /**
   * The audiences an audience mapper adds to the access token.
   *
   * @param mapper a protocol mapper
   * @return the audiences, empty for other mappers
   */
  static List<String> mapperAudiences(final ProtocolMapperModel mapper) {
    if (!AudienceProtocolMapper.PROVIDER_ID.equals(mapper.getProtocolMapper())) {
      return List.of();
    }
    final Map<String, String> config = mapper.getConfig();
    if (config == null || "false".equals(config.get(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN))) {
      return List.of();
    }
    return Stream.of(AudienceProtocolMapper.INCLUDED_CLIENT_AUDIENCE, AudienceProtocolMapper.INCLUDED_CUSTOM_AUDIENCE)
        .map(config::get)
        .filter(v -> v != null && !v.isBlank())
        .toList();
  }

  /**
   * The client's permission scopes: client scopes in the token scope that have no mappers.
   *
   * @param client the exchanging client
   * @return the names of the permission scopes
   */
  static Set<String> permissionScopes(final ClientModel client) {
    final Set<String> result = new LinkedHashSet<>();
    for (final boolean defaultScopes : new boolean[] { true, false }) {
      client.getClientScopes(defaultScopes).values().stream()
          .filter(s -> s.isIncludeInTokenScope() && s.getProtocolMappersStream().findAny().isEmpty())
          .forEach(s -> result.add(s.getName()));
    }
    return result;
  }

  /**
   * The scope claim of a subject token. Keycloak has already validated it when the mappers run.
   *
   * @param subjectToken the subject token, may be {@code null}
   * @return the scopes (empty if the token has none), or {@code null} if it is not a JWT
   */
  static List<String> subjectTokenScopes(final String subjectToken) {
    if (subjectToken == null) {
      return null;
    }
    try {
      return scopes(new JWSInput(subjectToken).readJsonContent(AccessToken.class).getScope());
    }
    catch (final JWSInputException | RuntimeException e) {
      return null;
    }
  }

  /**
   * Values of a request parameter from the query string and the form body. Values separated by commas count as
   * several values.
   *
   * @param session the Keycloak session
   * @param form the form parameters, may be {@code null}
   * @param name the parameter name
   * @return the values in order, without duplicates
   */
  static Set<String> requestedValues(final KeycloakSession session, final MultivaluedMap<String, String> form,
      final String name) {
    final Set<String> values = new LinkedHashSet<>();
    splitValues(values, session.getContext().getUri().getQueryParameters().get(name));
    if (form != null) {
      splitValues(values, form.get(name));
    }
    return values;
  }

  /**
   * Adds values, split on commas and trimmed, to a set.
   *
   * @param into the set
   * @param values the values, may be {@code null}
   */
  static void splitValues(final Set<String> into, final Collection<String> values) {
    if (values == null) {
      return;
    }
    values.stream()
        .flatMap(v -> Arrays.stream(v.split(",")))
        .map(String::trim)
        .filter(v -> !v.isEmpty())
        .forEach(into::add);
  }

  private static List<String> scopes(final String scope) {
    return scope == null ? List.of() : Arrays.stream(scope.split(" ")).filter(s -> !s.isEmpty()).toList();
  }

  private static boolean isEnabled(final ProtocolMapperModel mapper, final String key) {
    final String value = mapper.getConfig() == null ? null : mapper.getConfig().get(key);
    return value == null || Boolean.parseBoolean(value);
  }

  private static MultivaluedMap<String, String> formParameters(final KeycloakSession session) {
    try {
      return session.getContext().getHttpRequest().getDecodedFormParameters();
    }
    catch (final RuntimeException e) {
      return null;
    }
  }

  /** at_hash for an encoded access token, computed the way Keycloak's TokenManager does it. */
  private static String oidcHash(final KeycloakSession session, final String input) {
    final String algorithm = session.tokens().signatureAlgorithm(TokenCategory.ID);
    final String hashAlgorithm = session.getProvider(SignatureProvider.class, algorithm).signer().getHashAlgorithm();
    return HashUtils.encodeHashToOIDC(session.getProvider(HashProvider.class, hashAlgorithm).hash(input));
  }
}
