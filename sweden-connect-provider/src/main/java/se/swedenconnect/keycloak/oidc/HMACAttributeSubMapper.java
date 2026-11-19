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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Predicate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
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
  private static final List<String> SUPPORTED_HMAC_ALGORITHMS = List.of("HmacSHA256", "HmacSHA384", "HmacSHA512");
  // RFC 2104 discourages keys shorter than the HMAC output length.
  private static final Map<String, Integer> MINIMUM_KEY_LENGTHS = Map.of(
      "HmacSHA256", 32,
      "HmacSHA384", 48,
      "HmacSHA512", 64);

  private final ConcurrentMap<HmacConfiguration, Mac> hmacInstances = new ConcurrentHashMap<>();

  @Override
  public void validateConfig(
      final KeycloakSession session,
      final RealmModel realm,
      final ProtocolMapperContainerModel mapperContainer,
      final ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
    // Keycloak resolves messageKey as a message bundle key and formats the result with MessageFormat,
    // so every exception needs a key and messages must not contain quotes or braces.
    final var config = mapperModel.getConfig();
    if (getAttributeNames(mapperModel).isEmpty()) {
      throw new ProtocolMapperConfigException("Configure at least one user attribute for HMAC input.",
          "hmacSubMapperMissingAttributes");
    }

    final String key = config.get(HMAC_KEY);
    if (key == null || key.isEmpty()) {
      throw new ProtocolMapperConfigException("Configure a non-empty HMAC key.", "hmacSubMapperMissingKey");
    }
    final String algorithm = Optional.ofNullable(mapperModel.getConfig()
                                      .get(HMAC_ALGORITHM))
                                      .filter(NOT_BLANK)
                                      .orElse(DEFAULT_HMAC_ALGORITHM);
    try {
      initializeHmac(new HmacConfiguration(algorithm, key));
    }
    catch (final NoSuchAlgorithmException e) {
      throw new ProtocolMapperConfigException("HMAC algorithm must be one of " +
              String.join(", ", SUPPORTED_HMAC_ALGORITHMS)
          + ".", "hmacSubMapperUnsupportedAlgorithm", e);
    }
    catch (final InvalidKeyException e) {
      throw new ProtocolMapperConfigException("HMAC key must be at least " + MINIMUM_KEY_LENGTHS.get(algorithm)
          + " bytes for " + algorithm + ".", "hmacSubMapperKeyTooShort", e);
    }
    catch (final GeneralSecurityException | IllegalArgumentException e) {
      throw new ProtocolMapperConfigException("Unable to initialize the configured HMAC algorithm and key.",
          "hmacSubMapperInvalidHmac", e);
    }

    final String encoding = Optional.ofNullable(mapperModel.getConfig()
                                      .get(SUB_ENCODING))
                                      .filter(NOT_BLANK)
                                      .orElse(DEFAULT_SUB_ENCODING);
    if (!"Base64".equals(encoding) && !"Hex".equals(encoding)) {
      throw new ProtocolMapperConfigException("Subject encoding must be Base64 or Hex.",
          "hmacSubMapperUnsupportedEncoding");
    }

    if (!isValidSubjectType(resolveSubjectType(mapperModel, null))) {
      throw new ProtocolMapperConfigException("Default subject type must be public or pairwise.",
          "hmacSubMapperUnsupportedSubjectType");
    }
    if (mapperContainer instanceof ClientModel client) {
      final String subjectType = resolveSubjectType(mapperModel, client);
      if (!isValidSubjectType(subjectType)) {
        throw new ProtocolMapperConfigException("Client attribute " + CLIENT_SUBJECT_TYPE
            + " must be public or pairwise.", "hmacSubMapperUnsupportedClientSubjectType");
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
      return token;
    }
    catch (final ErrorResponseException e) {
      throw e;
    }
    catch (final RuntimeException e) {
      // Fail closed: issuing the token with its previous subject could leak a non-pairwise identifier.
      log.errorf(e, "Unexpected error while mapping HMAC subject for %s", tokenType);
      throw mappingError("Unable to map subject");
    }
  }

  private static ErrorResponseException mappingError(final String description) {
    return new ErrorResponseException(
        OAuthErrorException.SERVER_ERROR, description, Response.Status.INTERNAL_SERVER_ERROR);
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
      throw mappingError("No user attributes are configured for HMAC input");
    }
    // Blank values are skipped, since all users with a blank value would otherwise share one subject.
    final String attributeValue = attributeNames.stream()
        .map(userSession.getUser()::getFirstAttribute)
        .filter(value -> value != null && !value.isBlank())
        .findFirst()
        .orElseThrow(() -> {
          log.errorf("Unable to set subject: none of the configured user attributes %s has a non-blank value",
              attributeNames);
          return mappingError("None of the configured subject attributes has a value");
        });

    final ClientModel client = clientSessionCtx == null || clientSessionCtx.getClientSession() == null
        ? null
        : clientSessionCtx.getClientSession().getClient();
    final String subjectType = resolveSubjectType(mappingModel, client);
    if (!isValidSubjectType(subjectType)) {
      log.errorf("Unsupported subject type '%s'", subjectType);
      throw mappingError("Unsupported subject type");
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
    return  Optional.ofNullable(mappingModel.getConfig()
                    .get(SUBJECT_TYPE))
                    .filter(NOT_BLANK)
                    .orElse(DEFAULT_SUBJECT_TYPE);
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
      throw mappingError("OIDC client is unavailable");
    }

    final String sectorUri = getSectorIdentifierUri(client);
    final String sector = sectorUri != null
        ? PairwiseSubMapperUtils.resolveValidSectorIdentifier(sectorUri)
        : PairwiseSubMapperUtils.resolveValidSectorIdentifier(client.getRootUrl(), client.getRedirectUris());
    if (sector == null || sector.isBlank()) {
      log.errorf("Unable to resolve pairwise sector identifier for client '%s'", client.getClientId());
      throw mappingError("Unable to resolve pairwise sector identifier");
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
    final String encoding = Optional.ofNullable(mappingModel.getConfig()
                                    .get(SUB_ENCODING))
                                    .filter(NOT_BLANK)
                                    .orElse(DEFAULT_SUB_ENCODING);
    return switch (encoding) {
    case "Base64" -> Base64.getEncoder().encodeToString(hash);
    case "Hex" -> HexFormat.of().formatHex(hash);
    default -> {
      log.errorf("Unsupported HMAC subject encoding '%s'", encoding);
      throw mappingError("Unsupported HMAC subject encoding");
    }
    };
  }

  private Mac getHmac(final ProtocolMapperModel mappingModel) {
    final String key = mappingModel.getConfig().get(HMAC_KEY);
    final String algorithm = Optional.ofNullable(mappingModel.getConfig()
                                    .get(HMAC_ALGORITHM))
                                    .filter(NOT_BLANK)
                                    .orElse(DEFAULT_HMAC_ALGORITHM);
    if (key == null || key.isEmpty()) {
      log.error("Unable to initialize HMAC for protocol mapper: HMAC key is missing");
      throw mappingError("Unable to initialize configured HMAC");
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
      throw mappingError("Unable to initialize configured HMAC");
    }
  }

  // Also enforced at token time, since realm imports do not run validateConfig.
  private static Mac initializeHmac(final HmacConfiguration configuration) throws GeneralSecurityException {
    final Integer minimumKeyLength = MINIMUM_KEY_LENGTHS.get(configuration.algorithm());
    if (minimumKeyLength == null) {
      throw new NoSuchAlgorithmException("Unsupported HMAC algorithm");
    }
    final byte[] key = configuration.key().getBytes(StandardCharsets.UTF_8);
    if (key.length < minimumKeyLength) {
      throw new InvalidKeyException("HMAC key must be at least " + minimumKeyLength + " bytes");
    }
    final Mac mac = Mac.getInstance(configuration.algorithm());
    mac.init(new SecretKeySpec(key, configuration.algorithm()));
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
            + "The first attribute with a non-blank value is used.");
    attributeNames.setType(ProviderConfigProperty.TEXT_TYPE);
    attributeNames.setRequired(true);

    final ProviderConfigProperty hmacKey = new ProviderConfigProperty();
    hmacKey.setName(HMAC_KEY);
    hmacKey.setLabel("HMAC Key");
    hmacKey.setHelpText("Symmetric key used to compute the subject HMAC. Must be at least 32 bytes for HmacSHA256, "
        + "48 bytes for HmacSHA384 and 64 bytes for HmacSHA512. Use a randomly generated key.");
    hmacKey.setType(ProviderConfigProperty.STRING_TYPE);
    hmacKey.setSecret(true);
    hmacKey.setRequired(true);

    final ProviderConfigProperty hmacAlgorithm = new ProviderConfigProperty();
    hmacAlgorithm.setName(HMAC_ALGORITHM);
    hmacAlgorithm.setLabel("HMAC Algorithm");
    hmacAlgorithm.setHelpText("HMAC algorithm used to compute the subject.");
    hmacAlgorithm.setType(ProviderConfigProperty.LIST_TYPE);
    hmacAlgorithm.setOptions(SUPPORTED_HMAC_ALGORITHMS);
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
