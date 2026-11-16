package se.swedenconnect.keycloak.oidc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.LogoutToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.mockito.Mockito;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HMACAttributeSubMapperTest {

  @Test
  void setsSubjectToBase64HmacOfConfiguredUserAttribute() throws Exception {
    final String attributeValue = "personnummer-value";
    final String key = "test-hmac-key";
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

  @Test
  void missingAttributeThrows() {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, "test-hmac-key"
    ));
    final IDToken token = new IDToken();

    assertThrows(ErrorResponseException.class, () -> new HMACAttributeSubMapper().transformIDToken(
        token, mapperModel, null, userSession("personalIdentityNumber", null), null
    ));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "pnr"})
  void appliesOptionalPrefixToAllTokenTypes(final String prefix) throws Exception {
    final Map<String, String> config = new HashMap<>(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, "test-hmac-key"
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
    mac.init(new SecretKeySpec("test-hmac-key".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
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
        "test-hmac-key"
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
    mac.init(new SecretKeySpec("test-hmac-key".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    final String expected = Base64.getEncoder().encodeToString(
        mac.doFinal("secondary-value".getBytes(StandardCharsets.UTF_8)));
    assertEquals(expected, token.getSubject());
  }

  @Test
  void hexEncodesMacValue() throws Exception {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, "test-hmac-key",
        HMACAttributeSubMapper.SUB_ENCODING, "Hex"
    ));
    final IDToken token = new HMACAttributeSubMapper().transformIDToken(
        new IDToken(), mapperModel, null,
        userSession("personalIdentityNumber", "personnummer-value"), null);

    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec("test-hmac-key".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    final String expected = java.util.HexFormat.of().formatHex(
        mac.doFinal("personnummer-value".getBytes(StandardCharsets.UTF_8)));
    assertEquals(expected, token.getSubject());
  }

  @Test
  void transformsIntrospectionAndLogoutSubjects() {
    final ProtocolMapperModel mapperModel = mapperModel(Map.of(
        HMACAttributeSubMapper.ATTRIBUTE_NAMES, "personalIdentityNumber",
        HMACAttributeSubMapper.HMAC_KEY, "test-hmac-key"
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
        HMACAttributeSubMapper.HMAC_KEY, "test-hmac-key",
        HMACAttributeSubMapper.SUBJECT_TYPE, "public"
    ));
    final ClientSessionContext clientSessionContext = clientSessionContext(
        "pairwise", "https://sector.example.org/sector.json");
    final IDToken token = new HMACAttributeSubMapper().transformIDToken(
        new IDToken(), mapperModel, null,
        userSession("personalIdentityNumber", "personnummer-value"), clientSessionContext);

    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec("test-hmac-key".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
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
        HMACAttributeSubMapper.HMAC_KEY, "test-hmac-key",
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
        HMACAttributeSubMapper.HMAC_KEY, "test-hmac-key",
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

    assertThrows(ErrorResponseException.class, () -> new HMACAttributeSubMapper().transformIDToken(
        new IDToken(), mapperModel, null,
        userSession("personalIdentityNumber", "personnummer-value"), clientSessionContext));
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
