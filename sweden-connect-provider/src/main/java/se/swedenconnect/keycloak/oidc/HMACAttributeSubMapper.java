/*
 * Copyright 2025-2026 Sweden Connect
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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Predicate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperContainerModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.LogoutTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.protocol.oidc.utils.PairwiseSubMapperUtils;
import org.keycloak.protocol.oidc.utils.PairwiseSubMapperValidator;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.LogoutToken;
import org.keycloak.services.ErrorResponseException;

/**
 * Generates public or pairwise OIDC subject identifiers from configured user attributes.
 *
 * @author Sweden Connect
 */
public class HMACAttributeSubMapper extends AbstractOIDCProtocolMapper
    implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper,
    TokenIntrospectionTokenMapper, LogoutTokenMapper {

  public static final Predicate<String> NOT_BLANK = Predicate.not(String::isBlank);
  private static final Logger log = Logger.getLogger(HMACAttributeSubMapper.class);

  public static final String ATTRIBUTE_NAMES = "attribute.names";
  public static final String HMAC_KEY = "hmac.key";
  public static final String HMAC_ALGORITHM = "hmac.algorithm";
  public static final String SUB_PREFIX = "sub.prefix";
  public static final String SUB_ENCODING = "sub.encoding";
  public static final String SUBJECT_TYPE = "subject.type";
  public static final String CLIENT_SUBJECT_TYPE = "oidc.subject.type";
  private static final String DEFAULT_HMAC_ALGORITHM = "HmacSHA256";
  private static final String DEFAULT_SUB_ENCODING = "Base64";
  private static final String DEFAULT_SUBJECT_TYPE = "public";

  private final ConcurrentMap<HmacConfiguration, Mac> hmacInstances = new ConcurrentHashMap<>();

  @Override
  public void validateConfig(
      final KeycloakSession session,
      final RealmModel realm,
      final ProtocolMapperContainerModel mapperContainer,
      final ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
    final var config = mapperModel.getConfig();
    if (getAttributeNames(mapperModel).isEmpty()) {
      throw new ProtocolMapperConfigException("Configure at least one user attribute for HMAC input.");
    }

    final String key = config.get(HMAC_KEY);
    if (key == null || key.isEmpty()) {
      throw new ProtocolMapperConfigException("Configure a non-empty HMAC key.");
    }
    final String algorithm = Optional.ofNullable(mapperModel.getConfig().get(HMAC_ALGORITHM)).filter(NOT_BLANK).orElse(DEFAULT_HMAC_ALGORITHM);
    try {
      initializeHmac(new HmacConfiguration(algorithm, key));
    }
    catch (final GeneralSecurityException | IllegalArgumentException e) {
      throw new ProtocolMapperConfigException("Unable to initialize the configured HMAC algorithm and key.", e);
    }

    final String encoding = Optional.ofNullable(mapperModel.getConfig().get(SUB_ENCODING)).filter(NOT_BLANK).orElse(DEFAULT_SUB_ENCODING);
    if (!"Base64".equals(encoding) && !"Hex".equals(encoding)) {
      throw new ProtocolMapperConfigException("Subject encoding must be Base64 or Hex.");
    }

    if (!isValidSubjectType(resolveSubjectType(mapperModel, null))) {
      throw new ProtocolMapperConfigException("Default subject type must be public or pairwise.");
    }
    if (mapperContainer instanceof ClientModel client) {
      final String subjectType = resolveSubjectType(mapperModel, client);
      if (!isValidSubjectType(subjectType)) {
        throw new ProtocolMapperConfigException("Client attribute 'oidc.subject.type' must be public or pairwise.");
      }
      if ("pairwise".equals(subjectType)) {
        validateSectorIdentifier(session, client);
      }
    }
  }

  private static void validateSectorIdentifier(final KeycloakSession session, final ClientModel client)
      throws ProtocolMapperConfigException {
    final String sectorUri = getSectorIdentifierUri(client);
    final String rootUrl = client.getRootUrl();
    final Set<String> redirectUris = client.getRedirectUris();
    PairwiseSubMapperValidator.validate(session, rootUrl, redirectUris, sectorUri);
    // Keycloak's validator can accept a single null host, which cannot produce a sector.
    if (sectorUri == null && PairwiseSubMapperUtils.resolveValidSectorIdentifier(rootUrl, redirectUris) == null) {
      throw new ProtocolMapperConfigException("Client redirect URIs must contain a valid host component.",
          PairwiseSubMapperValidator.PAIRWISE_CLIENT_REDIRECT_URIS_MISSING_HOST);
    }
  }

  @Override
  public AccessToken transformAccessToken(
      final AccessToken token,
      final ProtocolMapperModel mappingModel,
      final KeycloakSession session,
      final UserSessionModel userSession,
      final ClientSessionContext clientSessionCtx) {
    return mapSubject(token, "access token",
        () -> this.setSub(token, mappingModel, session, userSession, clientSessionCtx));
  }

  @Override
  public IDToken transformIDToken(
      final IDToken token,
      final ProtocolMapperModel mappingModel,
      final KeycloakSession session,
      final UserSessionModel userSession,
      final ClientSessionContext clientSessionCtx) {
    return mapSubject(token, "ID token",
        () -> this.setSub(token, mappingModel, session, userSession, clientSessionCtx));
  }

  @Override
  public AccessToken transformUserInfoToken(
      final AccessToken token,
      final ProtocolMapperModel mappingModel,
      final KeycloakSession session,
      final UserSessionModel userSession,
      final ClientSessionContext clientSessionCtx) {
    return mapSubject(token, "UserInfo",
        () -> this.setSub(token, mappingModel, session, userSession, clientSessionCtx, true));
  }

  @Override
  public AccessToken transformIntrospectionToken(
      final AccessToken token,
      final ProtocolMapperModel mappingModel,
      final KeycloakSession session,
      final UserSessionModel userSession,
      final ClientSessionContext clientSessionCtx) {
    return mapSubject(token, "introspection response",
        () -> this.setSub(token, mappingModel, session, userSession, clientSessionCtx));
  }

  @Override
  public LogoutToken transformLogoutToken(
      final LogoutToken token,
      final ProtocolMapperModel mappingModel,
      final KeycloakSession session,
      final UserSessionModel userSession,
      final ClientSessionContext clientSessionCtx) {
    return mapSubject(token, "logout token",
        () -> this.setSub(token, mappingModel, session, userSession, clientSessionCtx));
  }

  private static <T extends JsonWebToken> T mapSubject(final T token, final String tokenType, final Runnable mapping) {
    try {
      mapping.run();
    }
    catch (final ErrorResponseException | IllegalArgumentException e) {
      log.errorf(e, "Unable to map HMAC subject for %s; returning the original token", tokenType);
    }
    return token;
  }

  protected void setSub(
      final JsonWebToken token,
      final ProtocolMapperModel mappingModel,
      final KeycloakSession session,
      final UserSessionModel userSession,
      final ClientSessionContext clientSessionCtx) {
    this.setSub(token, mappingModel, session, userSession, clientSessionCtx, false);
  }

  private void setSub(
      final JsonWebToken token,
      final ProtocolMapperModel mappingModel,
      final KeycloakSession session,
      final UserSessionModel userSession,
      final ClientSessionContext clientSessionCtx,
      final boolean userInfoToken) {
    final List<String> attributeNames = getAttributeNames(mappingModel);
    if (attributeNames.isEmpty()) {
      log.error("Unable to set subject: no user attributes are configured for HMAC input");
      throw new ErrorResponseException("server_error",
          "No user attributes are configured for HMAC input", Response.Status.INTERNAL_SERVER_ERROR);
    }
    String attributeValue = null;
    String matchedAttribute = null;
    for (final String attributeName : attributeNames) {
      attributeValue = userSession.getUser().getFirstAttribute(attributeName);
      if (attributeValue != null) {
        matchedAttribute = attributeName;
        break;
      }
    }
    if (matchedAttribute == null) {
      log.errorf("Unable to set subject: none of the configured user attributes %s has a value",
          attributeNames);
      throw new ErrorResponseException("invalid_grant",
          "none of the configured subject attributes has a value", Response.Status.BAD_REQUEST);
    }

    final ClientModel client = clientSessionCtx == null || clientSessionCtx.getClientSession() == null
        ? null
        : clientSessionCtx.getClientSession().getClient();
    final String subjectType = resolveSubjectType(mappingModel, client);
    if (!isValidSubjectType(subjectType)) {
      log.errorf("Unsupported subject type '%s'", subjectType);
      throw new ErrorResponseException(
          "server_error", "Unsupported subject type", Response.Status.INTERNAL_SERVER_ERROR);
    }
    final byte[] input = "pairwise".equals(subjectType)
        ? this.pairwiseInput(attributeValue, getSectorIdentifier(client))
        : attributeValue.getBytes(StandardCharsets.UTF_8);

    final Mac mac = this.getHmac(mappingModel);
    final byte[] hash;
    synchronized (mac) {
      hash = mac.doFinal(input);
    }
    final String subject = this.encodeHash(hash, mappingModel);
    final String prefix = mappingModel.getConfig().get(SUB_PREFIX);
    final String resolvedSubject = prefix == null || prefix.isBlank() ? subject : prefix + "-" + subject;
    if (userInfoToken) {
      token.getOtherClaims().put("sub", resolvedSubject);
    }
    else {
      token.setSubject(resolvedSubject);
    }
  }

  private static String resolveSubjectType(final ProtocolMapperModel mappingModel, final ClientModel client) {
    if (client != null) {
      final String clientOverride = client.getAttribute(CLIENT_SUBJECT_TYPE);
      if (clientOverride != null && !clientOverride.isBlank()) {
        return clientOverride;
      }
    }
    return  Optional.ofNullable(mappingModel.getConfig().get(SUBJECT_TYPE)).filter(NOT_BLANK).orElse(DEFAULT_SUBJECT_TYPE);
  }

  private static boolean isValidSubjectType(final String subjectType) {
    return "public".equals(subjectType) || "pairwise".equals(subjectType);
  }

  private static String getSectorIdentifierUri(final ClientModel client) {
    final String sectorUri = client.getAttribute(OIDCConfigAttributes.SECTOR_IDENTIFIER_URI);
    return sectorUri == null || sectorUri.isBlank() ? null : sectorUri;
  }

  private static String getSectorIdentifier(final ClientModel client) {
    if (client == null) {
      log.error("Unable to create pairwise subject: OIDC client is unavailable");
      throw new ErrorResponseException(
          "server_error", "OIDC client is unavailable", Response.Status.INTERNAL_SERVER_ERROR);
    }

    final String sectorUri = getSectorIdentifierUri(client);
    final String sector = sectorUri != null
        ? PairwiseSubMapperUtils.resolveValidSectorIdentifier(sectorUri)
        : PairwiseSubMapperUtils.resolveValidSectorIdentifier(client.getRootUrl(), client.getRedirectUris());
    if (sector == null || sector.isBlank()) {
      log.errorf("Unable to resolve pairwise sector identifier for client '%s'", client.getClientId());
      throw new ErrorResponseException("server_error",
          "Unable to resolve pairwise sector identifier", Response.Status.INTERNAL_SERVER_ERROR);
    }
    return sector;
  }

  private byte[] pairwiseInput(final String attributeValue, final String sector) {
    final byte[] sectorBytes = sector.getBytes(StandardCharsets.UTF_8);
    final byte[] attributeBytes = attributeValue.getBytes(StandardCharsets.UTF_8);
    // Length-prefix the sector to avoid ambiguous concatenation with arbitrary attribute values.
    final ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES + sectorBytes.length + attributeBytes.length);
    buffer.putInt(sectorBytes.length);
    buffer.put(sectorBytes);
    buffer.put(attributeBytes);
    return buffer.array();
  }

  private static List<String> getAttributeNames(final ProtocolMapperModel mappingModel) {
    final String configuredNames = mappingModel.getConfig().get(ATTRIBUTE_NAMES);
    if (configuredNames == null || configuredNames.isBlank()) {
      return List.of();
    }
    return configuredNames.lines()
        .map(String::trim)
        .filter(Predicate.not(String::isEmpty))
        .toList();
  }

  private String encodeHash(final byte[] hash, final ProtocolMapperModel mappingModel) {
    final String encoding = Optional.ofNullable(mappingModel.getConfig().get(SUB_ENCODING)).filter(NOT_BLANK).orElse(DEFAULT_SUB_ENCODING);
    return switch (encoding) {
    case "Base64" -> Base64.getEncoder().encodeToString(hash);
    case "Hex" -> HexFormat.of().formatHex(hash);
    default -> {
      log.errorf("Unsupported HMAC subject encoding '%s'", encoding);
      throw new ErrorResponseException("server_error",
          "Unsupported HMAC subject encoding", Response.Status.INTERNAL_SERVER_ERROR);
    }
    };
  }

  private Mac getHmac(final ProtocolMapperModel mappingModel) {
    final String key = mappingModel.getConfig().get(HMAC_KEY);
    final String algorithm = Optional.ofNullable(mappingModel.getConfig().get(HMAC_ALGORITHM)).filter(NOT_BLANK).orElse(DEFAULT_HMAC_ALGORITHM);
    if (key == null || key.isEmpty()) {
      final IllegalArgumentException exception = new IllegalArgumentException("HMAC key is missing");
      log.error("Unable to initialize HMAC for protocol mapper: HMAC key is missing");
      throw exception;
    }

    final HmacConfiguration configuration = new HmacConfiguration(algorithm, key);
    return this.hmacInstances.computeIfAbsent(configuration, this::createHmac);
  }

  private Mac createHmac(final HmacConfiguration configuration) {
    try {
      final Mac mac = initializeHmac(configuration);
      log.debugf("Initialized HMAC mapper using algorithm '%s'", configuration.algorithm());
      return mac;
    }
    catch (final GeneralSecurityException | IllegalArgumentException e) {
      log.errorf(e, "Unable to initialize HMAC mapper using algorithm '%s'", configuration.algorithm());
      throw new ErrorResponseException(
          "server_error", "Unable to initialize configured HMAC", Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  private static Mac initializeHmac(final HmacConfiguration configuration) throws GeneralSecurityException {
    final Mac mac = Mac.getInstance(configuration.algorithm());
    mac.init(new SecretKeySpec(configuration.key().getBytes(StandardCharsets.UTF_8), configuration.algorithm()));
    return mac;
  }

  private record HmacConfiguration(String algorithm, String key) {
  }

  @Override
  public String getDisplayCategory() {
    return "HMAC Attribute Sub Mapper";
  }

  @Override
  public String getDisplayType() {
    return "HMAC Attribute Sub Mapper";
  }

  @Override
  public String getHelpText() {
    return "Computes the subject as an HMAC of the first configured user attribute with a value. "
        + "Pairwise mode includes the sector identifier in the HMAC input. The mapper setting is "
        + "the default and can be overridden per client using the 'oidc.subject.type' client attribute.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    final ProviderConfigProperty attributeNames = new ProviderConfigProperty();
    attributeNames.setName(ATTRIBUTE_NAMES);
    attributeNames.setLabel("User Attributes");
    attributeNames.setHelpText(
        "User attribute names to try in order for the HMAC input, one name per line. "
            + "The first attribute with a non-null value is used.");
    attributeNames.setType(ProviderConfigProperty.TEXT_TYPE);
    attributeNames.setRequired(true);

    final ProviderConfigProperty hmacKey = new ProviderConfigProperty();
    hmacKey.setName(HMAC_KEY);
    hmacKey.setLabel("HMAC Key");
    hmacKey.setHelpText("Symmetric key used to compute the subject HMAC.");
    hmacKey.setType(ProviderConfigProperty.STRING_TYPE);
    hmacKey.setSecret(true);
    hmacKey.setRequired(true);

    final ProviderConfigProperty hmacAlgorithm = new ProviderConfigProperty();
    hmacAlgorithm.setName(HMAC_ALGORITHM);
    hmacAlgorithm.setLabel("HMAC Algorithm");
    hmacAlgorithm.setHelpText("HMAC algorithm used to compute the subject.");
    hmacAlgorithm.setType(ProviderConfigProperty.LIST_TYPE);
    hmacAlgorithm.setOptions(List.of("HmacSHA256", "HmacSHA384", "HmacSHA512"));
    hmacAlgorithm.setDefaultValue(DEFAULT_HMAC_ALGORITHM);

    final ProviderConfigProperty subPrefix = new ProviderConfigProperty();
    subPrefix.setName(SUB_PREFIX);
    subPrefix.setLabel("Subject Prefix");
    subPrefix.setHelpText(
        "Optional prefix added before the encoded HMAC, separated by '-'. Leave blank for no prefix.");
    subPrefix.setType(ProviderConfigProperty.STRING_TYPE);

    final ProviderConfigProperty subEncoding = new ProviderConfigProperty();
    subEncoding.setName(SUB_ENCODING);
    subEncoding.setLabel("Subject Encoding");
    subEncoding.setHelpText("Encoding for the HMAC in the subject.");
    subEncoding.setType(ProviderConfigProperty.LIST_TYPE);
    subEncoding.setOptions(List.of("Base64", "Hex"));
    subEncoding.setDefaultValue(DEFAULT_SUB_ENCODING);

    final ProviderConfigProperty subjectType = new ProviderConfigProperty();
    subjectType.setName(SUBJECT_TYPE);
    subjectType.setLabel("Default Subject Type");
    subjectType.setHelpText(
        "Default subject mapping mode. A client can override this using the 'oidc.subject.type' client attribute.");
    subjectType.setType(ProviderConfigProperty.LIST_TYPE);
    subjectType.setOptions(List.of("public", "pairwise"));
    subjectType.setDefaultValue(DEFAULT_SUBJECT_TYPE);

    return List.of(attributeNames, hmacKey, hmacAlgorithm, subPrefix, subEncoding, subjectType);
  }

  @Override
  public String getId() {
    return "HMAC-Attribute-Sub";
  }
}
