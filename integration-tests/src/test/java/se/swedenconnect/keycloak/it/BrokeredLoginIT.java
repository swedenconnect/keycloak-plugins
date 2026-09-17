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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.userprofile.config.UPConfig;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives complete brokered logins through the plugins the way a browser would, against a real
 * Keycloak of the targeted version, and asserts on what a relying party actually receives.
 *
 * <p>Three realms live in the one container:
 *
 * <pre>
 *   idp  - Keycloak as a SAML IdP. Asserts Sweden Connect attributes (urn:oid:...) for user "anna".
 *   op   - Keycloak as an OIDC OP. Emits the Sweden Connect claims for the same user.
 *   sp   - the realm under test. Brokers to the two above through this repository's providers and
 *          mappers, and issues tokens to "test-client" through the Sweden Connect protocol mappers.
 * </pre>
 *
 * <p>Each test walks one of the broker paths end to end (client authorization request, IdP button,
 * auto-submitted SAML forms or OIDC redirects, IdP login form, back to the broker, first-broker-login,
 * authorization code, token exchange, UserInfo) and then checks the tokens, the UserInfo response,
 * the persisted user, or the SP metadata.
 *
 * <p>This is the layer the unit tests and {@link ProviderRegistrationIT} cannot reach: a Keycloak
 * release changing how a broker callback, a mapper hook or a session note behaves at runtime shows
 * up here as a missing claim or a stuck login rather than as a compile error.
 *
 * @author David Goldring
 */
class BrokeredLoginIT {

  private static final ObjectMapper JSON = new ObjectMapper();

  // ---- What the fake IdP/OP asserts about the user, and what must come out the other end. ----
  private static final String PNR = "197309069289";
  private static final String GIVEN_NAME = "Nina";
  private static final String FAMILY_NAME = "Greger";
  private static final String DISPLAY_NAME = "Nina Greger";
  private static final String BIRTHDATE = "1973-09-06";
  private static final String USERNAME = "nina";
  private static final String PASSWORD = "password";

  // ---- Sweden Connect SAML attribute names (see AttributeToClaim) and their OIDC claims. ----
  private static final String PNR_ATTRIBUTE = "urn:oid:1.2.752.29.4.13";
  private static final String GIVEN_NAME_ATTRIBUTE = "urn:oid:2.5.4.42";
  private static final String FAMILY_NAME_ATTRIBUTE = "urn:oid:2.5.4.4";
  private static final String DISPLAY_NAME_ATTRIBUTE = "urn:oid:2.16.840.1.113730.3.1.241";
  private static final String BIRTHDATE_ATTRIBUTE = "urn:oid:1.3.6.1.5.5.7.9.1";
  private static final String PNR_CLAIM = "https://id.oidc.se/claim/personalIdentityNumber";
  private static final String NUMBER_SCOPE = "https://id.oidc.se/scope/naturalPersonNumber";
  private static final String INFO_SCOPE = "https://id.oidc.se/scope/naturalPersonInfo";
  private static final String KEYCLOAK_SAML_ACR = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

  private static final String IDP_REALM = "idp";
  private static final String OP_REALM = "op";
  private static final String SP_REALM = "sp";
  private static final String CLIENT_ID = "test-client";
  private static final String OP_CLIENT_ID = "sp-broker";
  private static final String OP_CLIENT_SECRET = "sp-broker-secret";
  private static final String SAML_PERSISTENT = "saml-persistent";
  private static final String SAML_TRANSIENT = "saml-transient";
  private static final String OIDC_PROXY = "proxy-oidc";
  private static final String ORG_NAME = "Testmyndigheten";
  private static final String ENTITY_CATEGORY = "http://id.elegnamnden.se/ec/1.0/loa3-pnr";
  private static final String CANCEL_STATUS = "http://id.elegnamnden.se/status/1.0/cancel";

  private static Keycloak admin;
  private static String base;
  private static String redirectUri;

  @BeforeAll
  static void configureRealms() {
    final KeycloakContainer keycloak = KeycloakServer.start();
    base = keycloak.getAuthServerUrl();
    redirectUri = base + "/done";
    admin = keycloak.getKeycloakAdminClient();

    createSamlIdpRealm();
    createOidcOpRealm();
    createSpRealm();
  }

  @AfterAll
  static void closeAdmin() {
    if (Objects.nonNull(admin)) {
      admin.close();
    }
  }

  // ===========================================================================================
  // Tests
  // ===========================================================================================

  /**
   * SAML broker with persisted users: Sweden-Connect-SAML-Mapper turns the assertion into a real
   * Keycloak user, taking the username from the configured personnummer attribute and the names
   * from their {@code urn:oid} attributes, and links that user to the broker.
   *
   * <p>No Sweden Connect <em>claims</em> are asserted here, because they do not reach the token in
   * this mode. Sweden-Connect-SAML-Mapper stores the assertion under the
   * {@code SAML_ATTRIBUTES_JSON} user session note, which the Sweden-Connect protocol mapper reads,
   * and Keycloak's first-broker-login {@code resetFlow} clears that note. It is only repopulated as
   * attributes on the lightweight user when {@code doNotStoreUsers=true}. The claim path is
   * therefore covered by {@link #samlBrokeredLoginWithTransientUsersIssuesSwedenConnectClaims()},
   * which is the mode the Sweden Connect proxy realms actually run in.
   */
  @Test
  void samlBrokeredLoginPersistsUserFromTheAssertion() {
    final Browser browser = new Browser();
    final String code = loginThroughSaml(browser, SAML_PERSISTENT);
    final Tokens tokens = exchange(browser, code);

    assertFalse(String.valueOf(tokens.idToken().get("sub")).startsWith("lightweight-"),
        "Users are persisted for this broker, so the subject must not be a transient user");
    assertEquals(CLIENT_ID, tokens.accessToken().get("client_id"), "client_id claim set by the Sweden-Connect mapper");

    // Sweden-Connect-SAML-Mapper (attribute.username.key) sets the created user's username to the
    // personnummer carried in that SAML attribute, not to the IdP's own "anna" login name.
    final UserRepresentation user = admin.realm(SP_REALM).users().search(PNR, true).stream()
        .filter(u -> PNR.equals(u.getUsername()))
        .findFirst()
        .orElseThrow(() -> new AssertionError("No user with username '" + PNR + "' was created in the sp realm"));
    final UserRepresentation full = admin.realm(SP_REALM).users().get(user.getId()).toRepresentation();
    assertEquals(GIVEN_NAME, full.getFirstName(), "first name taken from urn:oid:2.5.4.42");
    assertEquals(FAMILY_NAME, full.getLastName(), "last name taken from urn:oid:2.5.4.4");
    final List<String> links = admin.realm(SP_REALM).users().get(user.getId()).getFederatedIdentity().stream()
        .map(FederatedIdentityRepresentation::getIdentityProvider)
        .toList();
    assertTrue(links.contains(SAML_PERSISTENT), "user is linked to the broker, links: " + links);
  }

  /**
   * SAML broker with {@code doNotStoreUsers=true}, which is how the Sweden Connect proxy realms
   * are deployed. The mappers then also populate user attributes on the lightweight user, and the
   * acr from the assertion's AuthnContext must reach the id token.
   */
  @Test
  void samlBrokeredLoginWithTransientUsersIssuesSwedenConnectClaims() {
    final Browser browser = new Browser();
    final String code = loginThroughSaml(browser, SAML_TRANSIENT);
    final Tokens tokens = exchange(browser, code);

    assertTrue(String.valueOf(tokens.idToken().get("sub")).startsWith("lightweight-"),
        "doNotStoreUsers=true must produce a transient user, sub was " + tokens.idToken().get("sub"));
    assertEquals(PNR, tokens.idToken().get(PNR_CLAIM), "personalIdentityNumber claim in the id token");
    assertEquals(KEYCLOAK_SAML_ACR, tokens.idToken().get("acr"),
        "acr taken from the assertion's AuthnContextClassRef (the built-in acr scope is not on the client)");

    assertEquals(PNR, tokens.accessToken().get(PNR_CLAIM), "personalIdentityNumber in the access token");
    assertEquals(CLIENT_ID, tokens.accessToken().get("client_id"), "client_id claim in the access token");

    final Map<String, Object> userInfo = tokens.userInfo();
    assertEquals(PNR, userInfo.get(PNR_CLAIM), "personalIdentityNumber in UserInfo");
    assertEquals(GIVEN_NAME, userInfo.get("given_name"), "given_name in UserInfo");
    assertEquals(FAMILY_NAME, userInfo.get("family_name"), "family_name in UserInfo");
    assertEquals(DISPLAY_NAME, userInfo.get("name"), "name in UserInfo");
    assertEquals(BIRTHDATE, userInfo.get("birthdate"), "birthdate in UserInfo");
  }

  /**
   * OIDC proxy: ProxyProvider (registered as {@code keycloak-oidc}) forwards the Sweden Connect
   * scopes the client asked for to the upstream OP, and Sweden-Connect-OP maps the claims that
   * come back onto the transient user so that the Sweden-Connect protocol mapper can issue them.
   */
  @Test
  void oidcProxyLoginForwardsScopesAndIssuesSwedenConnectClaims() {
    final Browser browser = new Browser();
    final String brokerLink = brokerLink(browser, OIDC_PROXY, NUMBER_SCOPE + " " + INFO_SCOPE, "st-" + UUID.randomUUID());

    // The broker answers the button click with a redirect to the OP; inspect it before following.
    final Browser.Page redirect = browser.getWithoutRedirect(brokerLink);
    final String upstream = redirect.location().orElseThrow(() -> new AssertionError(
        "Expected a redirect to the OP, got " + redirect.status() + ":\n" + excerpt(redirect.body())));
    assertTrue(upstream.startsWith(base + "/realms/" + OP_REALM + "/protocol/openid-connect/auth"),
        "Broker must redirect to the op realm, was " + upstream);
    final String upstreamScope = Browser.queryParameters(upstream).get("scope");
    assertNotNull(upstreamScope, "No scope forwarded upstream in " + upstream);
    final List<String> forwarded = List.of(upstreamScope.split(" "));
    assertTrue(forwarded.containsAll(List.of("openid", NUMBER_SCOPE, INFO_SCOPE)),
        "ProxyProvider must forward the requested Sweden Connect scopes, forwarded: " + forwarded);

    final Browser.Page opLogin = browser.get(upstream);
    final Browser.Page done = submitCredentials(browser, opLogin);
    final String code = authorizationCode(done);
    final Tokens tokens = exchange(browser, code);

    assertTrue(String.valueOf(tokens.idToken().get("sub")).startsWith("lightweight-"),
        "doNotStoreUsers=true must produce a transient user, sub was " + tokens.idToken().get("sub"));
    assertEquals(PNR, tokens.idToken().get(PNR_CLAIM), "personalIdentityNumber claim in the id token");
    assertEquals(PNR, tokens.accessToken().get(PNR_CLAIM), "personalIdentityNumber in the access token");

    final Map<String, Object> userInfo = tokens.userInfo();
    assertEquals(PNR, userInfo.get(PNR_CLAIM), "personalIdentityNumber in UserInfo");
    assertEquals(GIVEN_NAME, userInfo.get("given_name"), "given_name in UserInfo");
    assertEquals(FAMILY_NAME, userInfo.get("family_name"), "family_name in UserInfo");
    assertEquals(DISPLAY_NAME, userInfo.get("name"), "name in UserInfo");
    assertEquals(BIRTHDATE, userInfo.get("birthdate"), "birthdate in UserInfo");
  }

  /**
   * SwedenConnectSAMLEndpoint: a SAML response carrying the Sweden Connect cancel status must send
   * the user straight back to the client with {@code error=access_denied} and its {@code state},
   * instead of Keycloak's generic "unexpected error" page.
   *
   * <p>Keycloak's IdP cannot be made to emit that status, so the response is hand-built. That is
   * acceptable here because the broker is configured not to validate signatures; the same is true
   * of the Keycloak-issued responses in the other tests.
   */
  @Test
  void cancelledSamlResponseReturnsAccessDeniedToTheClient() {
    final Browser browser = new Browser();
    final String state = "cancel-" + UUID.randomUUID();
    final Browser.Page brokerPage = browser.get(brokerLink(browser, SAML_PERSISTENT, NUMBER_SCOPE, state));
    final Browser.Form authnRequest = Browser.formWith(brokerPage.body(), "SAMLRequest")
        .orElseThrow(() -> new AssertionError("No AuthnRequest form:\n" + excerpt(brokerPage.body())));
    final String relayState = authnRequest.fields().get("RelayState");
    assertNotNull(relayState, "AuthnRequest form carries no RelayState");

    final String brokerEndpoint = base + "/realms/" + SP_REALM + "/broker/" + SAML_PERSISTENT + "/endpoint";
    final Browser.Page result = browser.postFormWithoutRedirect(brokerEndpoint, Map.of(
        "SAMLResponse", Base64.getEncoder().encodeToString(cancelResponse(brokerEndpoint).getBytes(StandardCharsets.UTF_8)),
        "RelayState", relayState));

    assertEquals(200, result.status(), "Cancel handling renders a redirect page:\n" + excerpt(result.body()));
    final String expected = redirectUri + "?error=access_denied&error_description=Authentication+cancelled+by+user."
        + "&state=" + state;
    assertTrue(result.body().contains(expected),
        "Redirect page must send the client to " + expected + ":\n" + excerpt(result.body()));
  }

  /**
   * Sweden-Connect-SAML-Mapper also acts as a metadata updater: the SP metadata Keycloak publishes
   * for the broker must carry the organisation, contacts, entity categories and requested
   * attributes the federation requires.
   */
  @Test
  void spMetadataCarriesSwedenConnectExtensions() {
    final Browser.Page metadata = new Browser().get(
        base + "/realms/" + SP_REALM + "/broker/" + SAML_PERSISTENT + "/endpoint/descriptor");

    assertEquals(200, metadata.status(), "SP metadata:\n" + excerpt(metadata.body()));
    final String xml = metadata.body();
    assertTrue(xml.contains(ORG_NAME), "organisation name from the mapper config, in:\n" + excerpt(xml));
    assertTrue(xml.contains("tech@example.se"), "technical contact from the mapper config, in:\n" + excerpt(xml));
    assertTrue(xml.contains(ENTITY_CATEGORY), "entity category from the mapper config, in:\n" + excerpt(xml));
    assertTrue(xml.contains("Name=\"" + PNR_ATTRIBUTE + "\""),
        "requested attribute for the personnummer, in:\n" + excerpt(xml));
  }

  // ===========================================================================================
  // The flows
  // ===========================================================================================

  /**
   * Full SP-initiated SAML login: IdP button, AuthnRequest form, IdP login form, SAMLResponse form.
   *
   * @return the authorization code the sp realm finally issued to the client
   */
  private static String loginThroughSaml(final Browser browser, final String brokerAlias) {
    final String state = "st-" + UUID.randomUUID();
    final Browser.Page brokerPage = browser.get(brokerLink(browser, brokerAlias, NUMBER_SCOPE + " " + INFO_SCOPE, state));

    // The broker renders an auto-submitting AuthnRequest form aimed at the IdP.
    final Browser.Form authnRequest = Browser.formWith(brokerPage.body(), "SAMLRequest")
        .orElseThrow(() -> new AssertionError("No AuthnRequest form after the IdP button:\n" + excerpt(brokerPage.body())));
    final Browser.Page idpLogin = browser.submit(authnRequest, Map.of());

    final Browser.Page samlResponsePage = submitCredentials(browser, idpLogin);

    // The IdP answers with an auto-submitting SAMLResponse form aimed at the broker endpoint.
    final Browser.Form samlResponse = Browser.formWith(samlResponsePage.body(), "SAMLResponse")
        .orElseThrow(() -> new AssertionError("No SAMLResponse form after IdP login:\n" + excerpt(samlResponsePage.body())));
    final String assertion = new String(Base64.getDecoder().decode(samlResponse.fields().get("SAMLResponse")),
        StandardCharsets.UTF_8);
    Stream.of(PNR_ATTRIBUTE, GIVEN_NAME_ATTRIBUTE, FAMILY_NAME_ATTRIBUTE, DISPLAY_NAME_ATTRIBUTE, BIRTHDATE_ATTRIBUTE)
        .forEach(name -> assertTrue(assertion.contains("Name=\"" + name + "\""),
            "The IdP fixture did not assert " + name + " - the test set-up is broken, not the plugin"));

    final Browser.Page done = browser.submit(samlResponse, Map.of());
    final String code = authorizationCode(done);
    assertEquals(state, Browser.queryParameters(done.uri().toString()).get("state"), "state echoed back to the client");
    return code;
  }

  /**
   * Starts an authorization request at the sp realm for the test client and returns the login
   * page's button URL for the given broker.
   */
  private static String brokerLink(final Browser browser, final String brokerAlias, final String extraScopes,
      final String state) {
    final String authorization = base + "/realms/" + SP_REALM + "/protocol/openid-connect/auth?" + Browser.encode(Map.of(
        "client_id", CLIENT_ID,
        "response_type", "code",
        "scope", ("openid " + extraScopes).trim(),
        "redirect_uri", redirectUri,
        "state", state));
    final Browser.Page loginPage = browser.get(authorization);
    final String href = Browser.link(loginPage.body(), "/broker/" + brokerAlias + "/login")
        .orElseThrow(() -> new AssertionError(
            "No button for broker '" + brokerAlias + "' on the sp login page:\n" + excerpt(loginPage.body())));
    // Keycloak renders the button as a path-relative link.
    return loginPage.uri().resolve(href).toString();
  }

  /** Fills in Keycloak's username/password form on the given page and submits it. */
  private static Browser.Page submitCredentials(final Browser browser, final Browser.Page loginPage) {
    final Browser.Form form = Browser.formPostingTo(loginPage.body(), "login-actions/authenticate")
        .orElseThrow(() -> new AssertionError("No login form on the page:\n" + excerpt(loginPage.body())));
    return browser.submit(form, Map.of("username", USERNAME, "password", PASSWORD));
  }

  /**
   * The redirect_uri is not a real endpoint, so Keycloak's 404 for it is the success case; what
   * matters is that the browser was sent there with a code.
   */
  private static String authorizationCode(final Browser.Page done) {
    final String url = done.uri().toString();
    assertTrue(url.startsWith(redirectUri), "Login did not complete; ended at " + done.status() + " " + url
        + ":\n" + excerpt(done.body()));
    final String code = Browser.queryParameters(url).get("code");
    assertNotNull(code, "No authorization code in " + url);
    return code;
  }

  /** The decoded tokens of one login, plus a UserInfo lookup with the access token. */
  private record Tokens(Map<String, Object> idToken, Map<String, Object> accessToken, String rawAccessToken) {

    Map<String, Object> userInfo() {
      final Browser.Page page = new Browser().getWithBearer(
          base + "/realms/" + SP_REALM + "/protocol/openid-connect/userinfo", this.rawAccessToken);
      assertEquals(200, page.status(), "UserInfo:\n" + excerpt(page.body()));
      return json(page.body());
    }
  }

  private static Tokens exchange(final Browser browser, final String code) {
    final Browser.Page response = browser.postForm(base + "/realms/" + SP_REALM + "/protocol/openid-connect/token", Map.of(
        "grant_type", "authorization_code",
        "client_id", CLIENT_ID,
        "code", code,
        "redirect_uri", redirectUri));
    assertEquals(200, response.status(), "Token exchange:\n" + excerpt(response.body()));
    final Map<String, Object> body = json(response.body());
    final String accessToken = String.valueOf(body.get("access_token"));
    return new Tokens(jwtPayload(String.valueOf(body.get("id_token"))), jwtPayload(accessToken), accessToken);
  }

  // ===========================================================================================
  // Realm set-up
  // ===========================================================================================

  /** Keycloak as a SAML IdP that asserts the Sweden Connect attributes for user "anna". */
  private static void createSamlIdpRealm() {
    createRealm(IDP_REALM);

    final ClientRepresentation sp = new ClientRepresentation();
    sp.setClientId(spEntityId());
    sp.setProtocol("saml");
    sp.setEnabled(true);
    // Both SAML brokers share the entityId; the IdP picks the ACS from the AuthnRequest.
    sp.setRedirectUris(List.of(brokerEndpoint(SAML_PERSISTENT), brokerEndpoint(SAML_TRANSIENT)));
    sp.setAttributes(Map.of(
        "saml.client.signature", "false",
        "saml.assertion.signature", "false",
        "saml.server.signature", "false",
        "saml.authnstatement", "true",
        "saml_name_id_format", "username"));
    sp.setProtocolMappers(List.of(
        samlAttributeMapper(PNR_ATTRIBUTE, "pnr"),
        samlAttributeMapper(BIRTHDATE_ATTRIBUTE, "birthdate"),
        samlAttributeMapper(DISPLAY_NAME_ATTRIBUTE, "displayName"),
        samlPropertyMapper(GIVEN_NAME_ATTRIBUTE, "firstName"),
        samlPropertyMapper(FAMILY_NAME_ATTRIBUTE, "lastName")));
    created(admin.realm(IDP_REALM).clients().create(sp));

    createUser(IDP_REALM);
  }

  /** Keycloak as an OIDC OP that issues the Sweden Connect claims for user "anna". */
  private static void createOidcOpRealm() {
    createRealm(OP_REALM);
    createClientScope(OP_REALM, NUMBER_SCOPE);
    createClientScope(OP_REALM, INFO_SCOPE);

    final ClientRepresentation client = new ClientRepresentation();
    client.setClientId(OP_CLIENT_ID);
    client.setSecret(OP_CLIENT_SECRET);
    client.setPublicClient(false);
    client.setStandardFlowEnabled(true);
    client.setRedirectUris(List.of(brokerEndpoint(OIDC_PROXY)));
    client.setDefaultClientScopes(List.of("basic", "profile", "email"));
    client.setOptionalClientScopes(List.of(NUMBER_SCOPE, INFO_SCOPE));
    client.setProtocolMappers(List.of(
        oidcPropertyMapper("firstName", "given_name"),
        oidcPropertyMapper("lastName", "family_name"),
        oidcAttributeMapper("pnr", escapeDots(PNR_CLAIM)),
        oidcAttributeMapper("displayName", "name"),
        oidcAttributeMapper("birthdate", "birthdate")));
    created(admin.realm(OP_REALM).clients().create(client));

    createUser(OP_REALM);
  }

  /** The realm under test: brokers through the plugins, issues tokens through the plugins. */
  private static void createSpRealm() {
    createRealm(SP_REALM);
    disableReviewProfileOnFirstLogin(SP_REALM);
    createClientScope(SP_REALM, NUMBER_SCOPE);
    createClientScope(SP_REALM, INFO_SCOPE);

    final ClientRepresentation client = new ClientRepresentation();
    client.setClientId(CLIENT_ID);
    client.setPublicClient(true);
    client.setStandardFlowEnabled(true);
    client.setRedirectUris(List.of(base + "/*"));
    // No profile/email/acr scopes: every asserted claim must come from this repository's mappers.
    client.setDefaultClientScopes(List.of("basic"));
    client.setOptionalClientScopes(List.of(NUMBER_SCOPE, INFO_SCOPE));
    client.setProtocolMappers(List.of(swedenConnectProtocolMapper()));
    created(admin.realm(SP_REALM).clients().create(client));

    createSamlBroker(SAML_PERSISTENT, false, 1);
    createSamlBroker(SAML_TRANSIENT, true, 2);
    createOidcBroker(OIDC_PROXY, "keycloak-oidc");
    addIdpMapper(OIDC_PROXY, "Sweden-Connect-OP", Map.of("syncMode", "INHERIT"));
  }

  /**
   * Creates a SAML broker against the throwaway IdP realm.
   *
   * <p><strong>Signature validation is deliberately off here, and this configuration must not be
   * copied into a deployment.</strong> The fake IdP has no key material the broker trusts, and the
   * cancel test hand-builds an unsigned response, so {@code validateSignature},
   * {@code wantAssertionsSigned} and {@code wantAuthnRequestsSigned} are all false. That is
   * acceptable against a container that lives for the duration of one test run.
   *
   * <p>In production these must be on. CVE-2026-2092 is an unauthorized-access flaw in Keycloak's
   * SAML broker endpoint: encrypted assertions are not properly validated when the overall SAML
   * response is unsigned, letting a holder of one valid signed assertion inject an encrypted
   * assertion for an arbitrary principal. Every Keycloak from 26.5.0 onwards is affected and no
   * fixed release exists yet, so requiring signed responses is the mitigation.
   */
  private static void createSamlBroker(final String alias, final boolean transientUsers, final int acsIndex) {
    final Map<String, String> config = new HashMap<>(Map.of(
        "singleSignOnServiceUrl", base + "/realms/" + IDP_REALM + "/protocol/saml",
        "entityId", spEntityId(),
        "nameIDPolicyFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "principalType", "SUBJECT",
        "postBindingAuthnRequest", "true",
        "postBindingResponse", "true",
        "validateSignature", "false",
        "wantAuthnRequestsSigned", "false",
        "wantAssertionsSigned", "false",
        "syncMode", "IMPORT"));
    config.put("attributeConsumingServiceIndex", String.valueOf(acsIndex));
    config.put("doNotStoreUsers", String.valueOf(transientUsers));
    createBroker(alias, "saml", config);

    addIdpMapper(alias, "Sweden-Connect-SAML-Mapper", Map.of(
        "syncMode", "INHERIT",
        "attribute.username.key", PNR_ATTRIBUTE,
        "attribute.org.sv.name", ORG_NAME,
        "attribute.org.sv.uri", "https://example.se",
        "attribute.contact.technical.email", "tech@example.se",
        "attribute.contact.support.email", "support@example.se",
        "attribute.entity.key", "[{\"key\":\"0\",\"value\":\"" + ENTITY_CATEGORY + "\"}]"));
  }

  /**
   * The browser-facing URLs use the mapped host port; the server-to-server URLs (token, JWKS,
   * UserInfo) are called by the sp realm from inside the container, where the op realm is
   * localhost:8080.
   */
  private static void createOidcBroker(final String alias, final String providerId) {
    final String internal = KeycloakServer.INTERNAL_URL + "/realms/" + OP_REALM + "/protocol/openid-connect";
    final Map<String, String> config = new HashMap<>(Map.of(
        "authorizationUrl", base + "/realms/" + OP_REALM + "/protocol/openid-connect/auth",
        "tokenUrl", internal + "/token",
        "jwksUrl", internal + "/certs",
        "userInfoUrl", internal + "/userinfo",
        "useJwksUrl", "true",
        "validateSignature", "true",
        "clientId", OP_CLIENT_ID,
        "clientSecret", OP_CLIENT_SECRET,
        "clientAuthMethod", "client_secret_post",
        "defaultScope", "openid"));
    config.put("doNotStoreUsers", "true");
    config.put("syncMode", "IMPORT");
    createBroker(alias, providerId, config);
  }

  private static void createBroker(final String alias, final String providerId, final Map<String, String> config) {
    final IdentityProviderRepresentation broker = new IdentityProviderRepresentation();
    broker.setAlias(alias);
    broker.setProviderId(providerId);
    broker.setEnabled(true);
    broker.setTrustEmail(true);
    broker.setFirstBrokerLoginFlowAlias("first broker login");
    broker.setConfig(config);
    created(admin.realm(SP_REALM).identityProviders().create(broker));
  }

  private static void addIdpMapper(final String brokerAlias, final String mapperId, final Map<String, String> config) {
    final IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
    mapper.setName(mapperId);
    mapper.setIdentityProviderAlias(brokerAlias);
    mapper.setIdentityProviderMapper(mapperId);
    mapper.setConfig(new HashMap<>(config));
    created(admin.realm(SP_REALM).identityProviders().get(brokerAlias).addMapper(mapper));
  }

  /** The Sweden-Connect protocol mapper with one explicit access-token mapping. */
  private static ProtocolMapperRepresentation swedenConnectProtocolMapper() {
    final ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
    mapper.setName("sweden-connect");
    mapper.setProtocol("openid-connect");
    mapper.setProtocolMapper("Sweden-Connect");
    mapper.setConfig(new HashMap<>(Map.of(
        "attribute.access.token.key", "[{\"key\":\"" + PNR_ATTRIBUTE + "\",\"value\":\"" + PNR_CLAIM + "\"}]")));
    return mapper;
  }

  private static ProtocolMapperRepresentation samlAttributeMapper(final String attributeName, final String userAttribute) {
    final ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
    mapper.setName(userAttribute);
    mapper.setProtocol("saml");
    mapper.setProtocolMapper("saml-user-attribute-mapper");
    mapper.setConfig(new HashMap<>(Map.of(
        "attribute.name", attributeName,
        "attribute.nameformat", "URI Reference",
        "user.attribute", userAttribute)));
    return mapper;
  }

  private static ProtocolMapperRepresentation samlPropertyMapper(final String attributeName, final String userProperty) {
    final ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
    mapper.setName(userProperty);
    mapper.setProtocol("saml");
    mapper.setProtocolMapper("saml-user-property-mapper");
    mapper.setConfig(new HashMap<>(Map.of(
        "attribute.name", attributeName,
        "attribute.nameformat", "URI Reference",
        "user.attribute", userProperty)));
    return mapper;
  }

  private static ProtocolMapperRepresentation oidcPropertyMapper(final String userProperty, final String claim) {
    final ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
    mapper.setName(claim);
    mapper.setProtocol("openid-connect");
    mapper.setProtocolMapper("oidc-usermodel-property-mapper");
    mapper.setConfig(new HashMap<>(Map.of(
        "user.attribute", userProperty,
        "claim.name", claim,
        "jsonType.label", "String",
        "id.token.claim", "true",
        "access.token.claim", "true",
        "userinfo.token.claim", "true")));
    return mapper;
  }

  /**
   * Escapes the dots in a claim name so Keycloak's {@code OIDCAttributeMapperHelper} emits a single
   * flat claim rather than splitting the name into a nested JSON object. The real upstream Sweden
   * Connect OP emits flat claims; a Keycloak stand-in has to opt out of the path-splitting to match.
   */
  private static String escapeDots(final String claim) {
    return claim.replace(".", "\\.");
  }

  private static ProtocolMapperRepresentation oidcAttributeMapper(final String userAttribute, final String claim) {
    final ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
    mapper.setName(userAttribute);
    mapper.setProtocol("openid-connect");
    mapper.setProtocolMapper("oidc-usermodel-attribute-mapper");
    mapper.setConfig(new HashMap<>(Map.of(
        "user.attribute", userAttribute,
        "claim.name", claim,
        "jsonType.label", "String",
        "id.token.claim", "true",
        "access.token.claim", "true",
        "userinfo.token.claim", "true")));
    return mapper;
  }

  private static void createRealm(final String name) {
    final RealmRepresentation realm = new RealmRepresentation();
    realm.setRealm(name);
    realm.setEnabled(true);
    admin.realms().create(realm);
    relaxUserProfile(name);
  }

  /**
   * Keycloak's declarative user profile would otherwise interfere twice: unmanaged attributes are
   * rejected by default, which silently drops the {@code urn:oid:...} attributes the mappers set,
   * and a required email/first/last name makes VERIFY_PROFILE stop the login before the code is
   * issued. The mappers set no email.
   */
  private static void relaxUserProfile(final String realm) {
    final UPConfig profile = admin.realm(realm).users().userProfile().getConfiguration();
    profile.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ENABLED);
    Stream.of("email", "firstName", "lastName")
        .map(profile::getAttribute)
        .filter(Objects::nonNull)
        .forEach(attribute -> attribute.setRequired(null));
    admin.realm(realm).users().userProfile().update(profile);
  }

  /** Lets first-broker-login complete without a human confirming the profile. */
  private static void disableReviewProfileOnFirstLogin(final String realm) {
    final AuthenticationManagementResource flows = admin.realm(realm).flows();
    final AuthenticationExecutionInfoRepresentation reviewProfile = flows.getExecutions("first broker login").stream()
        .filter(execution -> "idp-review-profile".equals(execution.getProviderId()))
        .findFirst()
        .orElseThrow(() -> new AssertionError("No idp-review-profile execution in the first broker login flow"));

    final AuthenticatorConfigRepresentation config = new AuthenticatorConfigRepresentation();
    config.setAlias("review profile config");
    config.setConfig(new HashMap<>(Map.of("update.profile.on.first.login", "off")));
    if (Objects.nonNull(reviewProfile.getAuthenticationConfig())) {
      config.setId(reviewProfile.getAuthenticationConfig());
      flows.updateAuthenticatorConfig(reviewProfile.getAuthenticationConfig(), config);
    }
    else {
      created(flows.newExecutionConfig(reviewProfile.getId(), config));
    }
  }

  private static void createClientScope(final String realm, final String name) {
    final ClientScopeRepresentation scope = new ClientScopeRepresentation();
    scope.setName(name);
    scope.setProtocol("openid-connect");
    scope.setAttributes(Map.of("include.in.token.scope", "true", "display.on.consent.screen", "false"));
    created(admin.realm(realm).clientScopes().create(scope));
  }

  private static void createUser(final String realm) {
    final CredentialRepresentation password = new CredentialRepresentation();
    password.setType(CredentialRepresentation.PASSWORD);
    password.setValue(PASSWORD);
    password.setTemporary(false);

    final UserRepresentation user = new UserRepresentation();
    user.setUsername(USERNAME);
    user.setEnabled(true);
    user.setEmail(USERNAME + "@example.se");
    user.setEmailVerified(true);
    user.setFirstName(GIVEN_NAME);
    user.setLastName(FAMILY_NAME);
    user.setAttributes(Map.of(
        "pnr", List.of(PNR),
        "birthdate", List.of(BIRTHDATE),
        "displayName", List.of(DISPLAY_NAME)));
    user.setCredentials(List.of(password));
    created(admin.realm(realm).users().create(user));
  }

  // ===========================================================================================
  // Small helpers
  // ===========================================================================================

  private static String spEntityId() {
    return base + "/realms/" + SP_REALM;
  }

  private static String brokerEndpoint(final String alias) {
    return base + "/realms/" + SP_REALM + "/broker/" + alias + "/endpoint";
  }

  /** An unsigned SAML response with the Sweden Connect cancel status nested under Responder. */
  private static String cancelResponse(final String destination) {
    return """
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_%s" Version="2.0" IssueInstant="%s" Destination="%s">
          <saml:Issuer>%s</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
              <samlp:StatusCode Value="%s"/>
            </samlp:StatusCode>
            <samlp:StatusMessage>User cancelled</samlp:StatusMessage>
          </samlp:Status>
        </samlp:Response>
        """.formatted(UUID.randomUUID(), Instant.now(), destination, base + "/realms/" + IDP_REALM, CANCEL_STATUS);
  }

  private static void created(final Response response) {
    try (response) {
      final int status = response.getStatus();
      assertTrue(status >= 200 && status < 300,
          "Keycloak admin call failed with " + status + ": " + response.readEntity(String.class));
    }
  }

  private static Map<String, Object> jwtPayload(final String jwt) {
    final String[] parts = jwt.split("\\.");
    assertEquals(3, parts.length, "Not a JWT: " + jwt);
    return json(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
  }

  private static Map<String, Object> json(final String text) {
    try {
      return JSON.readValue(text, new TypeReference<>() {
      });
    }
    catch (final IOException e) {
      throw new UncheckedIOException("Not JSON: " + excerpt(text), e);
    }
  }

  private static String excerpt(final String body) {
    return Objects.isNull(body) ? "" : body.length() > 1500 ? body.substring(0, 1500) + "..." : body;
  }
}
