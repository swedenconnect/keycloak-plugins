package se.swedenconnect.keycloak.saml;

import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * An extension to KeyCloak's {@link SAMLIdentityProviderFactory} where Sweden Connect specific features are added.
 *
 * @author Martin Lindström
 */
public class SwedenConnectSamlIdentityProviderFactory extends SAMLIdentityProviderFactory {

  public static final String PROVIDER_ID = "saml-swedenconnect";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getName() {
    return "Sweden Connect SAML v2.0";
  }

  @Override
  public SAMLIdentityProvider create(final KeycloakSession session, final IdentityProviderModel model) {
    // TODO
    return super.create(session, model);
  }


}
