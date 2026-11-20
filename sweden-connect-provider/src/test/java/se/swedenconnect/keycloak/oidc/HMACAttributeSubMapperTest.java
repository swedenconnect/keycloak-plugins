package se.swedenconnect.keycloak.oidc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.OAuthErrorException;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.utils.PairwiseSubMapperValidator;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.LogoutToken;
import org.keycloak.services.ErrorResponseException;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HMACAttributeSubMapperTest {

  private static final String KEY = "test-hmac-key-with-sixty-four-bytes-0123456789-abcdefghijklmnopq";

  @Test
  void setsSubjectToBase64HmacOfConfiguredUserAttribute() throws Exception {
    final String attributeValue = "personnummer-value";
    final String key = KEY;
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, key,
        HMACAttributeSubMapper.HMAC_ALGORITHM, "HmacSHA256"
    ));
    final UserSessionModel userSession = userSession("personalIdentityNumber", attributeValue);
    final IDToken token = new IDToken();

    new HMACAttributeSubMapper().transformIDToken(
        token, mapperModel, null, userSession, null
    );

    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    final String expected = Base64.getEncoder().encodeToString(
        mac.doFinal(attributeValue.getBytes(StandardCharsets.UTF_8))
    );
    assertEquals(expected, token.getSubject());
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" \t"})
  void missingOrBlankAttributeFailsAllTokenTypes(final String attributeValue) {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY
    ));
    final HMACAttributeSubMapper mapper = new HMACAttributeSubMapper();
    final UserSessionModel userSession = userSession("personalIdentityNumber", attributeValue);

    assertServerError(() -> mapper.transformIDToken(new IDToken(), mapperModel, null, userSession, null));
    assertServerError(() -> mapper.transformAccessToken(new AccessToken(), mapperModel, null, userSession, null));
    assertServerError(() -> mapper.transformUserInfoToken(new AccessToken(), mapperModel, null, userSession, null));
    assertServerError(
        () -> mapper.transformIntrospectionToken(new AccessToken(), mapperModel, null, userSession, null));
    assertServerError(() -> mapper.transformLogoutToken(new LogoutToken(), mapperModel, null, userSession, null));
  }

  @Test
  void skipsBlankAttributeValues() throws Exception {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "blank\nempty\npersonalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY
    ));
    final Map<String, String> attributes = new LinkedHashMap<>();
    attributes.put("blank", " ");
    attributes.put("empty", "");
    attributes.put("personalIdentityNumber", "personnummer-value");

    final IDToken token = new HMACAttributeSubMapper().transformIDToken(
        new IDToken(), mapperModel, null, userSession(attributes), null);

    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    assertEquals(Base64.getEncoder().encodeToString(
        mac.doFinal("personnummer-value".getBytes(StandardCharsets.UTF_8))), token.getSubject());
  }

  @ParameterizedTest
  @CsvSource({"HmacSHA256, 31", "HmacSHA384, 47", "HmacSHA512, 63"})
  void rejectsTooShortKeyAtTokenTime(final String algorithm, final int keyLength) {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY.substring(0, keyLength),
        HMACAttributeSubMapper.HMAC_ALGORITHM, algorithm
    ));

    assertServerError(() -> new HMACAttributeSubMapper().transformIDToken(
        new IDToken(), mapperModel, null, userSession("personalIdentityNumber", "personnummer-value"), null));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "pnr"})
  void appliesOptionalPrefixToAllTokenTypes(final String prefix) throws Exception {
    final Map<String, String> config = new HashMap<>(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY
    ));
    if (prefix != null) {
      config.put(HMACAttributeSubMapper.SUB_PREFIX, prefix);
    }
    final ProtocolMapperModel mapperModel = mapperModel(config);
    final UserSessionModel userSession = userSession("personalIdentityNumber", "personnummer-value");
    final HMACAttributeSubMapper mapper = new HMACAttributeSubMapper();
    final IDToken idToken = mapper.transformIDToken(new IDToken(), mapperModel, null, userSession, null);
    final AccessToken accessToken = mapper.transformAccessToken(
        new AccessToken(), mapperModel, null, userSession, null);
    final AccessToken userInfo = mapper.transformUserInfoToken(
        new AccessToken(), mapperModel, null, userSession, null);

    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    final String hash = Base64.getEncoder().encodeToString(
        mac.doFinal("personnummer-value".getBytes(StandardCharsets.UTF_8)));
    final String expected = prefix == null || prefix.isBlank() ? hash : prefix + "-" + hash;
    assertEquals(expected, idToken.getSubject());
    assertEquals(expected, accessToken.getSubject());
    assertEquals(expected, userInfo.getOtherClaims().get("sub"));
  }

  @Test
  void usesFirstNonNullAttributeInConfiguredOrder() throws Exception {
    final Map<String, String> config = Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES,
        "primaryId\nsecondaryId\nfallbackId",
        HMACAttributeSubMapper.HMAC_KEY,
        KEY
    );
    final ProtocolMapperModel mapperModel = mapperModel(config);
    final Map<String, String> attributes = new LinkedHashMap<>();
    attributes.put("primaryId", null);
    attributes.put("secondaryId", "secondary-value");
    attributes.put("fallbackId", "fallback-value");
    final UserSessionModel userSession = userSession(attributes);
    final IDToken token = new HMACAttributeSubMapper().transformIDToken(
        new IDToken(), mapperModel, null, userSession, null);

    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    final String expected = Base64.getEncoder().encodeToString(
        mac.doFinal("secondary-value".getBytes(StandardCharsets.UTF_8)));
    assertEquals(expected, token.getSubject());
  }

  @Test
  void hexEncodesMacValue() throws Exception {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY,
        HMACAttributeSubMapper.SUB_ENCODING, "Hex"
    ));
    final IDToken token = new HMACAttributeSubMapper().transformIDToken(
        new IDToken(), mapperModel, null,
        userSession("personalIdentityNumber", "personnummer-value"), null);

    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    final String expected = java.util.HexFormat.of().formatHex(
        mac.doFinal("personnummer-value".getBytes(StandardCharsets.UTF_8)));
    assertEquals(expected, token.getSubject());
  }

  @Test
  void transformsIntrospectionAndLogoutSubjects() {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY
    ));
    final UserSessionModel userSession = userSession("personalIdentityNumber", "personnummer-value");
    final HMACAttributeSubMapper mapper = new HMACAttributeSubMapper();

    final AccessToken introspectionToken = mapper.transformIntrospectionToken(
        new AccessToken(), mapperModel, null, userSession, null);
    final LogoutToken logoutToken = mapper.transformLogoutToken(
        new LogoutToken(), mapperModel, null, userSession, null);

    assertEquals(introspectionToken.getSubject(), logoutToken.getSubject());
  }

  @Test
  void clientCanOverrideDefaultSubjectTypeToPairwise() throws Exception {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY,
        HMACAttributeSubMapper.SUBJECT_TYPE, "public"
    ));
    final ClientSessionContext clientSessionContext = clientSessionContext(
        "pairwise", "https://sector.example.org/sector.json");
    final IDToken token = new HMACAttributeSubMapper().transformIDToken(
        new IDToken(), mapperModel, null,
        userSession("personalIdentityNumber", "personnummer-value"), clientSessionContext);

    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    final byte[] sector = "sector.example.org".getBytes(StandardCharsets.UTF_8);
    final byte[] attribute = "personnummer-value".getBytes(StandardCharsets.UTF_8);
    final java.nio.ByteBuffer input = java.nio.ByteBuffer.allocate(Integer.BYTES + sector.length + attribute.length);
    input.putInt(sector.length).put(sector).put(attribute);
    final String expected = Base64.getEncoder().encodeToString(mac.doFinal(input.array()));
    assertEquals(expected, token.getSubject());
  }

  @Test
  void pairwiseSubjectsGroupClientsBySectorHost() {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY,
        HMACAttributeSubMapper.SUBJECT_TYPE, "pairwise"
    ));
    final UserSessionModel userSession = userSession("personalIdentityNumber", "personnummer-value");
    final HMACAttributeSubMapper mapper = new HMACAttributeSubMapper();

    final String firstSector = mapper.transformIDToken(
        new IDToken(), mapperModel, null, userSession,
        clientSessionContext(null, "https://sector-a.example.org/sector.json")
    ).getSubject();
    final String sameSector = mapper.transformIDToken(
        new IDToken(), mapperModel, null, userSession,
        clientSessionContext(null, "https://sector-a.example.org/other.json")
    ).getSubject();
    final String otherSector = mapper.transformIDToken(
        new IDToken(), mapperModel, null, userSession,
        clientSessionContext(null, "https://sector-b.example.org/sector.json")
    ).getSubject();

    assertEquals(firstSector, sameSector);
    org.junit.jupiter.api.Assertions.assertNotEquals(firstSector, otherSector);
  }

  @Test
  void pairwiseModeFailsWhenSectorCannotBeResolved() {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY,
        HMACAttributeSubMapper.SUBJECT_TYPE, "pairwise"
    ));
    final ClientSessionContext clientSessionContext = clientSessionContext("pairwise", null);
    final ClientModel client = clientSessionContext.getClientSession().getClient();
    when(client.getAttribute(OIDCConfigAttributes.SECTOR_IDENTIFIER_URI)).thenReturn(null);
    when(client.getRootUrl()).thenReturn(null);
    when(client.getRedirectUris()).thenReturn(java.util.Set.of(
        "https://one.example.org/callback",
        "https://two.example.org/callback"
    ));

    assertServerError(() -> new HMACAttributeSubMapper().transformIDToken(
        new IDToken(), mapperModel, null,
        userSession("personalIdentityNumber", "personnummer-value"), clientSessionContext));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" \t"})
  void usesDefaultsForNullOrBlankOptionalSettings(final String value) throws Exception {
    final ProtocolMapperModel defaults = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY
    ));
    final Map<String, String> config = new HashMap<>(defaults.getConfig());
    config.put(HMACAttributeSubMapper.HMAC_ALGORITHM, value);
    config.put(HMACAttributeSubMapper.SUB_ENCODING, value);
    config.put(HMACAttributeSubMapper.SUBJECT_TYPE, value);
    final ProtocolMapperModel nullOrBlankSettings = mapperModel(config);
    final HMACAttributeSubMapper mapper = new HMACAttributeSubMapper();
    final UserSessionModel userSession = userSession("personalIdentityNumber", "personnummer-value");

    mapper.validateConfig(null, null, mock(ClientModel.class), nullOrBlankSettings);
    final String defaultSubject = mapper.transformIDToken(new IDToken(), defaults, null, userSession, null).getSubject();
    final String subject = mapper.transformIDToken(new IDToken(), nullOrBlankSettings, null, userSession, null)
        .getSubject();
    assertEquals(defaultSubject, subject);
  }

  @ParameterizedTest
  @CsvSource({
      "attribute.names, '', hmacSubMapperMissingAttributes",
      "hmac.key, '', hmacSubMapperMissingKey",
      "hmac.key, short-key, hmacSubMapperKeyTooShort",
      "hmac.algorithm, unsupported, hmacSubMapperUnsupportedAlgorithm",
      "hmac.algorithm, HmacMD5, hmacSubMapperUnsupportedAlgorithm",
      "sub.encoding, unsupported, hmacSubMapperUnsupportedEncoding",
      "subject.type, unsupported, hmacSubMapperUnsupportedSubjectType"
  })
  void rejectsInvalidMapperSettings(final String setting, final String value, final String messageKey) {
    final var exception = assertThrows(ProtocolMapperConfigException.class, () ->
        new HMACAttributeSubMapper().validateConfig(
            null, null, mock(ClientScopeModel.class), validationModel(setting, value)));
    assertEquals(messageKey, exception.getMessageKey());
  }

  @ParameterizedTest
  @CsvSource({"HmacSHA256, 32", "HmacSHA384, 48", "HmacSHA512, 64"})
  void enforcesMinimumKeyLengthPerAlgorithm(final String algorithm, final int minimumKeyLength) throws Exception {
    final Map<String, String> config = new HashMap<>(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_ALGORITHM, algorithm
    ));
    final HMACAttributeSubMapper mapper = new HMACAttributeSubMapper();

    config.put(HMACAttributeSubMapper.HMAC_KEY, KEY.substring(0, minimumKeyLength - 1));
    final var exception = assertThrows(ProtocolMapperConfigException.class,
        () -> mapper.validateConfig(null, null, mock(ClientScopeModel.class), mapperModel(config)));
    assertEquals("hmacSubMapperKeyTooShort", exception.getMessageKey());

    config.put(HMACAttributeSubMapper.HMAC_KEY, KEY.substring(0, minimumKeyLength));
    mapper.validateConfig(null, null, mock(ClientScopeModel.class), mapperModel(config));
  }

  @Test
  void allowsPairwiseDefaultOnClientScopeWithoutClientSpecificSettings() throws Exception {
    new HMACAttributeSubMapper().validateConfig(null, null, mock(ClientScopeModel.class),
        validationModel(HMACAttributeSubMapper.SUBJECT_TYPE, "pairwise"));
  }

  @Test
  void publicClientOverrideDoesNotRequireSector() throws Exception {
    final ClientModel client = mock(ClientModel.class);
    when(client.getAttribute(HMACAttributeSubMapper.CLIENT_SUBJECT_TYPE)).thenReturn("public");
    when(client.getAttribute(OIDCConfigAttributes.SECTOR_IDENTIFIER_URI)).thenReturn("invalid URI");

    new HMACAttributeSubMapper().validateConfig(null, null, client,
        validationModel(HMACAttributeSubMapper.SUBJECT_TYPE, "pairwise"));
  }

  @Test
  void rejectsUnsupportedClientSubjectType() {
    final ClientModel client = mock(ClientModel.class);
    when(client.getAttribute(HMACAttributeSubMapper.CLIENT_SUBJECT_TYPE)).thenReturn("unsupported");

    assertThrows(ProtocolMapperConfigException.class, () -> new HMACAttributeSubMapper().validateConfig(
        null, null, client, validationModel(HMACAttributeSubMapper.SUBJECT_TYPE, "public")));
  }

  @Test
  void acceptsRedirectUrisWithSingleHost() throws Exception {
    final ClientModel client = mock(ClientModel.class);
    when(client.getRootUrl()).thenReturn("https://client.example.org");
    when(client.getRedirectUris()).thenReturn(Set.of("/callback", "https://client.example.org/other"));

    new HMACAttributeSubMapper().validateConfig(null, null, client,
        validationModel(HMACAttributeSubMapper.SUBJECT_TYPE, "pairwise"));
  }

  @ParameterizedTest
  @CsvSource({
      "https://one.example.org/callback, https://two.example.org/callback, pairwiseClientRedirectURIsMultipleHosts",
      "app:/callback, app:/other, pairwiseClientRedirectURIsMissingHost"
  })
  void rejectsRedirectUrisWithoutSingleSector(
      final String firstRedirect, final String secondRedirect, final String messageKey) {
    final ClientModel client = mock(ClientModel.class);
    when(client.getAttribute(HMACAttributeSubMapper.CLIENT_SUBJECT_TYPE)).thenReturn("pairwise");
    when(client.getRedirectUris()).thenReturn(Set.of(firstRedirect, secondRedirect));

    final var exception = assertThrows(ProtocolMapperConfigException.class, () ->
        new HMACAttributeSubMapper().validateConfig(null, null, client,
            validationModel(HMACAttributeSubMapper.SUBJECT_TYPE, "public")));
    assertEquals(messageKey, exception.getMessageKey());
  }

  @ParameterizedTest
  @ValueSource(strings = {"https://invalid host/sector.json", "https:/sector.json", "//sector.example.org/sector.json"})
  void rejectsMalformedSectorIdentifierUri(final String sectorUri) {
    final ClientModel client = mock(ClientModel.class);
    when(client.getAttribute(OIDCConfigAttributes.SECTOR_IDENTIFIER_URI)).thenReturn(sectorUri);
    when(client.getRedirectUris()).thenReturn(Set.of("https://client.example.org/callback"));

    final var exception = assertThrows(ProtocolMapperConfigException.class, () ->
        new HMACAttributeSubMapper().validateConfig(null, null, client,
            validationModel(HMACAttributeSubMapper.SUBJECT_TYPE, "pairwise")));
    assertEquals(PairwiseSubMapperValidator.PAIRWISE_MALFORMED_SECTOR_IDENTIFIER_URI, exception.getMessageKey());
  }

  @Test
  void validatesRedirectUrisFromSectorIdentifierUri() throws Exception {
    final String sectorUri = "https://sector.example.org/sector.json";
    final String firstRedirect = "https://one.example.org/callback";
    final String secondRedirect = "https://two.example.org/callback";
    final ClientModel client = mock(ClientModel.class);
    when(client.getAttribute(OIDCConfigAttributes.SECTOR_IDENTIFIER_URI)).thenReturn(sectorUri);
    when(client.getRedirectUris()).thenReturn(Set.of(firstRedirect, secondRedirect));
    final KeycloakSession session = mock(KeycloakSession.class);
    final HttpClientProvider http = mock(HttpClientProvider.class);
    when(session.getProvider(HttpClientProvider.class)).thenReturn(http);
    when(http.getString(sectorUri)).thenReturn("[\"%s\", \"%s\"]".formatted(firstRedirect, secondRedirect));
    final ProtocolMapperModel config = validationModel(HMACAttributeSubMapper.SUBJECT_TYPE, "pairwise");
    final HMACAttributeSubMapper mapper = new HMACAttributeSubMapper();

    mapper.validateConfig(session, null, client, config);

    when(http.getString(sectorUri)).thenReturn("[\"%s\"]".formatted(firstRedirect));
    final var exception = assertThrows(ProtocolMapperConfigException.class,
        () -> mapper.validateConfig(session, null, client, config));
    assertEquals(PairwiseSubMapperValidator.PAIRWISE_REDIRECT_URIS_MISMATCH, exception.getMessageKey());
  }

  private static void assertServerError(final Executable executable) {
    final var exception = assertThrows(ErrorResponseException.class, executable);
    assertEquals(OAuthErrorException.SERVER_ERROR, exception.getError());
  }

  private static ProtocolMapperModel validationModel(final String setting, final String value) {
    final Map<String, String> config = new HashMap<>(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, KEY
    ));
    config.put(setting, value);
    return mapperModel(config);
  }

  private static ClientSessionContext clientSessionContext(final String subjectType, final String sectorUri) {
    final ClientModel client = mock(ClientModel.class);
    when(client.getAttribute(HMACAttributeSubMapper.CLIENT_SUBJECT_TYPE)).thenReturn(subjectType);
    when(client.getAttribute(OIDCConfigAttributes.SECTOR_IDENTIFIER_URI)).thenReturn(sectorUri);
    when(client.getClientId()).thenReturn("test-client");
    final AuthenticatedClientSessionModel clientSession = mock(AuthenticatedClientSessionModel.class);
    when(clientSession.getClient()).thenReturn(client);
    final ClientSessionContext context = mock(ClientSessionContext.class);
    when(context.getClientSession()).thenReturn(clientSession);
    return context;
  }

  private static ProtocolMapperModel mapperModel(final Map<String, String> config) {
    final ProtocolMapperModel mapperModel = new ProtocolMapperModel();
    mapperModel.setConfig(config);
    return mapperModel;
  }

  private static UserSessionModel userSession(final String attributeName, final String value) {
    return userSession(java.util.Collections.singletonMap(attributeName, value));
  }

  private static UserSessionModel userSession(final Map<String, String> attributes) {
    final UserSessionModel userSession = Mockito.mock(UserSessionModel.class);
    final UserModel user = Mockito.mock(UserModel.class);
    when(userSession.getUser()).thenReturn(user);
    attributes.forEach((name, value) -> when(user.getFirstAttribute(name)).thenReturn(value));
    return userSession;
  }
}
