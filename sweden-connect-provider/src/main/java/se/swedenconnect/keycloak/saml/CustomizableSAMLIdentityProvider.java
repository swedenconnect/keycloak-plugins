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
package se.swedenconnect.keycloak.saml;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlSessionUtils;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.SAML2AuthnRequestBuilder;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.SAML2RequestedAuthnContextBuilder;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.api.saml.v2.request.SAML2Request;
import org.keycloak.saml.processing.core.util.KeycloakKeySamlExtensionGenerator;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Iterator;
import java.util.function.Consumer;
import java.util.function.Function;

public class CustomizableSAMLIdentityProvider extends SAMLIdentityProvider {
  public CustomizableSAMLIdentityProvider(final KeycloakSession session, final SAMLIdentityProviderConfig config, final DestinationValidator destinationValidator) {
    super(session, config, destinationValidator);
  }


  @Override
  public Response performLogin(final AuthenticationRequest request) {
    SAML2RequestedAuthnContextBuilder requestedAuthnContext = (new SAML2RequestedAuthnContextBuilder()).setComparison(((SAMLIdentityProviderConfig) this.getConfig()).getAuthnContextComparisonType());

    return this.performCustom(request, a -> a
        .subject("subject")
        .issuer("issuer")
    );
  }

  private Response performCustom(final AuthenticationRequest request, Consumer<SAML2AuthnRequestBuilder> customize) {
    try {
      UriInfo uriInfo = request.getUriInfo();
      RealmModel realm = request.getRealm();
      String issuerURL = super.getEntityId(uriInfo, realm);
      String destinationUrl = getConfig().getSingleSignOnServiceUrl();
      String nameIDPolicyFormat = getConfig().getNameIDPolicyFormat();

      if (nameIDPolicyFormat == null) {
        nameIDPolicyFormat =  JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get();
      }

      String protocolBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();

      String assertionConsumerServiceUrl = request.getRedirectUri();

      if (getConfig().isArtifactBindingResponse()) {
        protocolBinding = JBossSAMLURIConstants.SAML_HTTP_ARTIFACT_BINDING.get();
      } else if (getConfig().isPostBindingResponse()) {
        protocolBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get();
      }

      SAML2RequestedAuthnContextBuilder requestedAuthnContext =
          new SAML2RequestedAuthnContextBuilder()
              .setComparison(getConfig().getAuthnContextComparisonType());

      for (String authnContextClassRef : getAuthnContextClassRefUris())
        requestedAuthnContext.addAuthnContextClassRef(authnContextClassRef);

      for (String authnContextDeclRef : getAuthnContextDeclRefUris())
        requestedAuthnContext.addAuthnContextDeclRef(authnContextDeclRef);

      Integer attributeConsumingServiceIndex = getConfig().getAttributeConsumingServiceIndex();

      String loginHint = getConfig().isLoginHint() ? request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM) : null;
      Boolean allowCreate = null;
      if (getConfig().getConfig().get(SAMLIdentityProviderConfig.ALLOW_CREATE) == null || getConfig().isAllowCreate())
        allowCreate = Boolean.TRUE;
      LoginProtocol protocol = session.getProvider(LoginProtocol.class, request.getAuthenticationSession().getProtocol());
      Boolean forceAuthn = getConfig().isForceAuthn();
      if (protocol.requireReauthentication(null, request.getAuthenticationSession()))
        forceAuthn = Boolean.TRUE;
      SAML2AuthnRequestBuilder authnRequestBuilder = new SAML2AuthnRequestBuilder()
          .assertionConsumerUrl(assertionConsumerServiceUrl)
          .destination(destinationUrl)
          .issuer(issuerURL)
          .forceAuthn(forceAuthn)
          .protocolBinding(protocolBinding)
          .nameIdPolicy(SAML2NameIDPolicyBuilder
              .format(nameIDPolicyFormat)
              .setAllowCreate(allowCreate))
          .attributeConsumingServiceIndex(attributeConsumingServiceIndex)
          .requestedAuthnContext(requestedAuthnContext)
          .subject(loginHint);

      customize.accept(authnRequestBuilder);

      JaxrsSAML2BindingBuilder binding = new JaxrsSAML2BindingBuilder(session)
          .relayState(request.getState().getEncoded());
      boolean postBinding = getConfig().isPostBindingAuthnRequest();

      if (getConfig().isWantAuthnRequestsSigned()) {
        KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);

        String keyName = getConfig().getXmlSigKeyInfoKeyNameTransformer().getKeyName(keys.getKid(), keys.getCertificate());
        binding.signWith(keyName, keys.getPrivateKey(), keys.getPublicKey(), keys.getCertificate())
            .signatureAlgorithm(getSignatureAlgorithm())
            .signDocument();
        if (! postBinding && getConfig().isAddExtensionsElementWithKeyInfo()) {    // Only include extension if REDIRECT binding and signing whole SAML protocol message
          authnRequestBuilder.addExtension(new KeycloakKeySamlExtensionGenerator(keyName));
        }
      }

      AuthnRequestType authnRequest = authnRequestBuilder.createAuthnRequest();
      for(Iterator<SamlAuthenticationPreprocessor> it = SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext(); ) {
        authnRequest = it.next().beforeSendingLoginRequest(authnRequest, request.getAuthenticationSession());
      }

      if (authnRequest.getDestination() != null) {
        destinationUrl = authnRequest.getDestination().toString();
      }

      // Save the current RequestID in the Auth Session as we need to verify it against the ID returned from the IdP
      request.getAuthenticationSession().setClientNote(SamlProtocol.SAML_REQUEST_ID_BROKER, authnRequest.getID());

      if (postBinding) {
        return binding.postBinding(SAML2Request.convert(authnRequest)).request(destinationUrl);
      } else {
        return binding.redirectBinding(SAML2Request.convert(authnRequest)).request(destinationUrl);
      }
    } catch (Exception e) {
      throw new IdentityBrokerException("Could not create authentication request.", e);
    }
  }

  @Override
  public void authenticationFinished(final AuthenticationSessionModel authSession, final BrokeredIdentityContext context) {
    super.authenticationFinished(authSession, context);
  }
}
