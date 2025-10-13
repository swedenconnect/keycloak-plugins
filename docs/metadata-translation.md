# Rules for translating metadata between SAML and OpenID Connect

### Version: 1.0 - draft 01 - 2025-09-24

## Table of Contents

1. [**SAML to OpenID Connect**](#saml-to-openid-connect)

    1.1. [Generic Mappings](#generic-mappings)

    1.1.1. [Entity ID](#entity-id)

    1.1.2. [Entity Categories](#entity-categories)
    
    1.1.3. [UI Info](#ui-info)

    1.1.4. [Organization](#organization)
    
    1.1.5. [Contact Persons](#contact-persons)

    1.2. [Identity Provider Metadata](#idp-metadata)

    1.2.1. [Assurance Certification](#assurance-certification)
    
    1.2.2. [Entity Categories](#idp-entity-categories)
    
    1.2.3. [UI Info Mapping](#idp-ui-info-mapping)
    
    1.2.4. [Organization Mapping](#idp-organization-mapping)
    
    1.2.5. [Contacts Mapping](#idp-contacts-mapping)
    
    1.2.6. [Support for Sign Services](#support-for-sign-services)

    1.2.7. [Translation to OpenID Provider Metadata](#translation-to-openid-provider-metadata)
        
    1.3. [Service Provider Metadata](#sp-metadata)

    1.3.1. [Entity Categories](#sp-entity-categories)
    
    1.3.2. [UI Info Mapping](#sp-ui-info-mapping)

    1.3.3. [Organization Mapping](#sp-organization-mapping)
    
    1.3.4. [Contacts Mapping](#sp-contacts-mapping)

    1.3.5. [Translation to OIDC Relying Party Metadata](#translation-to-oidc-relying-party-metadata)
    
2. [**OpenID Connect to SAML**](#openid-connect-to-saml)

---

<a name="saml-to-openid-connect"></a>
## 1. SAML to OpenID Connect

Rules for translating SAML metadata into OpenID Connect metadata.

<a name="generic-mappings"></a>
### 1.1. Generic Mappings

This section contains mappings of SAML metadata elements that are commons for both IdPs and SPs.

<a name="entity-id"></a>
#### 1.1.1. Entity ID

The `entityID` attribute under a SAML `<md:EntityDescriptor>` SHOULD be translated into an URL that matches where the corresponding OP/RP is deployed.

Other naming rules are deployment specific.

<a name="entity-categories"></a>
#### 1.1.2. Entity Categories

For the entity categories, i.e., the attribute values given for the `http://macedir.org/entity-category` attribute under `<mdattr:EntityAttributes>` MUST be translated according to the rules defined in this section.

##### 1.1.2.1. Service Entity Categories

Section 2 of [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html#definitions-for-service-entity-categories) defines service entity categories. 

The interpretation of these categories differs depending on whether the declaration is made by an IdP or an SP. See [Section 1.2.2](#idp-entity-categories) for Identity Provider mappings and [Section 1.3.1](#sp-entity-categories) for Service Provider mappings.

##### 1.1.2.2. Service Property Categories

Section 3 of [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html#definitions-for-service-property-categories) defines Service Property Categories.

Service property categories such as `http://id.elegnamnden.se/sprop/1.0/mobile-auth` and `http://id.elegnamnden.se/sprop/1.0/scal2` have no mapping to a corresponding OIDC construct (and there is probably no such need in the future).

##### 1.1.2.3. Service Type Entity Categories

Section 4 of [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html#definitions-for-service-type-entity-categories) defines Service Type Entity Categories.

The defined Service Type Entity Category values only apply the Service Providers. See [Section 1.3.1](#sp-entity-categories). 

##### 1.1.2.4. Service Contract Categories

See Section 5 of [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html#service-contract-categories).

Service Contract Categories are prefixed with `http://id.swedenconnect.se/contract/` and indicate that an entity delivers or consumes services under a specific contract.

This information must be represented outside OIDC metadata. Instead, OpenID Federation trustmarks MUST be used.

> Currently, there are Service Contract Category values defined by parties other than Digg, for example to denote bilateral agreements. How these should be translated into trustmarks needs to be investigated.

##### 1.1.2.5. General Entity Categories

See Section 6 of [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html#general-entity-categories).

The `http://id.swedenconnect.se/general-ec/1.0/secure-authenticator-binding` category has no mapping to OIDC (will probably not be needed).

The `http://id.swedenconnect.se/general-ec/1.0/accepts-coordination-number` is SP-specific. See [Section 1.3.1](#sp-entity-categories).

The `http://id.swedenconnect.se/general-ec/1.0/supports-user-message` is IdP-specific. See [Section 1.2.2](#idp-entity-categories).

<a name=ui-info"></a>
#### 1.1.3. UI Info

Under both a `<md:IDPSSODescriptor>` element for Identity Providers and under a `<md:SPSSODescriptor>` element for Service Providers there may be an `<mdui:UIInfo>` extension. 

The following translations rules apply for this information:

- `<mdui:DisplayName>` elements are translated into `client_name`<sup>1</sup> and `display_name`<sup>2</sup> for OIDC Relying Parties and to `display_name`<sup>2</sup> for OpenID Providers.

- `<mdui:Logo>` - OAuth 2.0/OIDC only supports one logotype for each language, and therefore, if there are several logotypes (for the same language) under a `<mdui:UIInfo>` only one can be represented using the `logi_uri` parameter. This parameter is defined for clients in both \[1\] and \[2\] and for OP:s in \[2\].

- `<mdui:Description>` - Is represented using the `description`<sup>2</sup> claim.

Language support should be preserved, but to increase interoperability you should also include a claim without a language tag (using the same value as for Swedish, if available).

See [Section 1.2.3](#idp-ui-info-mapping) for the IdP-to-OP mapping and [Section 1.3.2](#sp-ui-info-mapping) for the SP-to-RP mapping.

> \[1\]: Defined in [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html).
>
> \[2\]: Defined in [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html#name-informational-metadata-exte).

<a name="organization"></a>
#### 1.1.4. Organization

A mapping of the information found under the `<md:Organization>` element requires using the newly defined claims in Section 5.2.2 of [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html#name-informational-metadata-exte).

The following translations rules apply for this information:

- `<md:OrganizationName>` is mapped to `organization_name`.

- No mapping exists for `<md:OrganizationDisplayName>`

- `<md:OrganizationURL>` is mapped to `organization_uri`.

Language support should be preserved, but to increase interoperability you should also include a claim without a language tag (using the same value as for Swedish, if available).

See [Section 1.2.4](#idp-organization-mapping) for the IdP-to-OP mapping and [Section 1.3.3](#sp-organization-mapping) for the SP-to-RP mapping.

<a name="contact-persons"></a>
#### 1.1.5. Contact Persons

The SAML element `<md:ContactPerson>` is a complex element that can store the following information:

- Type of contact,
- company,
- given name,
- surname,
- email address(es), and,
- telephone number(s).

The OpenID Connect equivalent is the `contacts` claim as defined in Section 5.2.2 of [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html#name-informational-metadata-exte). For OpenID Connect, the `contacts` claim is simply a JSON array holding contact information. Therefore, this document specifies the following mapping rules:

Traverse over all `<md:ContactPerson>` elements and, and build a resulting JSON array of values:

- Ignore `<md:Company>`-elements.

- Only include `<md:GivenName>` and `<md:SurName>` if the resulting array of information otherwise would be empty. If used, combine the two values together to one string.

- Add each email address found under `<md:EmailAddress>`. Do not add a value that already has been added to the resulting array.

- Add each telephone number found under `<md:TelephoneNumber>`. Do not add a value that already has been added to the resulting array.

If the resulting array is empty, do not add the `contacts` claims to the metadata.

See [Section 1.2.5](#idp-contacts-mapping) for the IdP-to-OP mapping and [Section 1.3.4](#sp-contacts-mapping) for the SP-to-RP mapping.

<a name="idp-metadata"></a>
### 1.2. Identity Provider Metadata

Given the following SAML IdP metadata (Freja in Sweden Connect production), we specify how it should be translated to OpenID Connect metadata:

```xml
<md:EntityDescriptor entityID="https://idp-sweden-connect-valfr-2017.prod.frejaeid.com">
  <ds:Signature>
    ...
  </ds:Signature>
  <md:Extensions>
    <mdattr:EntityAttributes>
      <saml:Attribute Name="urn:oasis:names:tc:SAML:attribute:assurance-certification"
                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>http://id.elegnamnden.se/loa/1.0/loa3</saml:AttributeValue>
        <saml:AttributeValue>http://id.elegnamnden.se/loa/1.0/eidas-nf-sub</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://macedir.org/entity-category"
                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>http://id.elegnamnden.se/ec/1.0/loa3-pnr</saml:AttributeValue>
        <saml:AttributeValue>http://id.swedenconnect.se/ec/1.0/loa3-name</saml:AttributeValue>
        <saml:AttributeValue>http://id.elegnamnden.se/sprop/1.0/mobile-auth</saml:AttributeValue>
        <saml:AttributeValue>
          http://id.elegnamnden.se/ec/1.0/eidas-pnr-delivery
        </saml:AttributeValue>
        <saml:AttributeValue>
          http://id.swedenconnect.se/contract/sc/eid-choice-2017
        </saml:AttributeValue>
        <saml:AttributeValue>
          http://id.swedenconnect.se/general-ec/1.0/secure-authenticator-binding
        </saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </md:Extensions>
  <md:IDPSSODescriptor WantAuthnRequestsSigned="true" 
                       protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="en">Freja eID+</mdui:DisplayName>
        <mdui:DisplayName xml:lang="sv">Freja eID+</mdui:DisplayName>
        <mdui:Description xml:lang="en">
          Freja eID is an electronic identity on your mobile that allows you to log in, 
          sign and approve transactions. It comes with two levels of identity assurance, 
          basic level and Freja eID+, which is officially approved by the Swedish E-identification
          board with the quality mark Svensk e-legitimation. Freja eID+ gives you access to
          more services and a free ID protection, alerting you if your official residential 
          address is changed.
        </mdui:Description>
        <mdui:Description xml:lang="sv">
          Freja eID är en mobil e-legitimation som gör att du kan logga in, skriva under och 
          godkänna transaktioner hos anslutna tjänster. Den utfärdas i två olika tillitsnivåer, 
          Freja eID Bas och Freja eID+, varav den senare har statliga E-legitimationsnämnden 
          godkänt för kvalitetsmärket Svensk e-legitimation. Med Freja eID+ kan du nå
          ännu fler tjänster och får även ett ID-Skydd som varnar ifall någon ändrar din 
          folkbokföringsadress hos Skatteverket.
        </mdui:Description>
        <mdui:Logo height="75" width="75">
          https://idp-sweden-connect-valfr-2017.prod.frejaeid.com/idp/images/frejaeid_logo.svg
        </mdui:Logo>
        <mdui:Logo height="120" width="120">
          https://idp-sweden-connect-valfr-2017.prod.frejaeid.com/idp/images/frejaeid_logo_vertical.svg
        </mdui:Logo>
      </mdui:UIInfo>
    </md:Extensions>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIEsTCCAxmgAwIBAgIUW...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIEpDCCAwygA...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://idp-sweden-connect-valfr-2017.prod.frejaeid.com/idp/profile/SAML2/Redirect/SSO"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="https://idp-sweden-connect-valfr-2017.prod.frejaeid.com/idp/profile/SAML2/POST/SSO"/>
  </md:IDPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">Freja eID Group AB</md:OrganizationName>
    <md:OrganizationName xml:lang="sv">Freja eID Group AB</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">Freja eID Group AB</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="sv">Freja eID Group AB</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">https://frejaeid.com/en/</md:OrganizationURL>
    <md:OrganizationURL xml:lang="sv">https://frejaeid.com</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:Company>Freja eID Group AB</md:Company>
    <md:EmailAddress>partnersupport@frejaeid.com</md:EmailAddress>
  </md:ContactPerson>
  <md:ContactPerson contactType="support">
    <md:Company>Freja eID Group AB</md:Company>
    <md:EmailAddress>partnersupport@frejaeid.com</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>
```

<a name="assurance-certification"></a>
#### 1.2.1. Assurance Certification

The attribute values given for `assurance-certification` under `<mdattr:EntityAttributes>` should be mapped to `acr_values_supported`, which is an JSON array.

**Note:** All values published under `acr_values_supported` MUST be checked during OpenID Fed policy filtering.

Also note that these values should be mapped to trust marks.

```json
  "acr_values_supported" : [ "http://id.elegnamnden.se/loa/1.0/loa3", 
                             "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub" ],
```

<a name="idp-entity-categories"></a>
#### 1.2.2. Entity Categories

<a name="idp-service-entity-categories"></a>
##### 1.2.2.1. Service Entity Categories

Section 2 of [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html#definitions-for-service-entity-categories) defines a set of Service Entity Categories.

If service entity categories appears in IdP metadata, they are translated into corresponding `scopes` as defined in [Claims and Scopes Specification for the Swedish OpenID Connect Profile](https://www.oidc.se/specifications/swedish-oidc-claims-specification-1_0.html) and [OpenID Connect Claims and Scopes Specification for Sweden Connect](https://docs.swedenconnect.se/technical-framework/latest/OpenID_Connect_Claims_and_Scopes_Specification.html):

| Service Entity Category | OpenID Connect Scope |
| :--- | :--- |
| `http://id.elegnamnden.se/ec/1.0/loa2-pnr` or `http://id.elegnamnden.se/ec/1.0/loa3-pnr` or `http://id.elegnamnden.se/ec/1.0/loa4-pnr` | `https://id.oidc.se/scope/naturalPersonInfo` and `https://id.oidc.se/scope/naturalPersonNumber` |
| `http://id.swedenconnect.se/ec/1.0/loa2-name` or `http://id.swedenconnect.se/ec/1.0/loa3-name` or `http://id.swedenconnect.se/ec/1.0/loa4-name` | `https://id.oidc.se/scope/naturalPersonInfo` |
| `http://id.swedenconnect.se/ec/1.0/loa2-orgid` or `http://id.swedenconnect.se/ec/1.0/loa3-orgid` or `http://id.swedenconnect.se/ec/1.0/loa4-orgid` | `https://id.oidc.se/scope/naturalPersonOrgId` |
| `http://id.elegnamnden.se/ec/1.0/eidas-pnr-delivery` | `https://id.oidc.se/scope/naturalPersonInfo` and `https://id.oidc.se/scope/naturalPersonNumber` |
| `http://id.elegnamnden.se/ec/1.0/eidas-naturalperson` | `https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity` and `https://id.swedenconnect.se/scope/eidasSwedishIdentity` and `https://id.oidc.se/scope/naturalPersonInfo` |

**Note:** Make sure that the mapping does not generate multiple occurrences of the same scope.

Mapping from XML above:

```json
  "scopes_supported" : [ "openid, 
                          ..., 
                          "https://id.oidc.se/scope/naturalPersonInfo", 
                          "https://id.oidc.se/scope/naturalPersonNumber" ],
```

OpenID Connect scopes are essentially aliases for sets of claims. Therefore, an IdP that lists values in `scopes_supported` MUST also include the corresponding claims in the `claims_supported` parameter. For the example above, this translates to:

```json
  "claims_supported" : [ "family_name", "given_name", "middle_name", "name", "birthdate",
                         "https://id.oidc.se/claim/personalIdentityNumber",
                         "https://id.oidc.se/claim/coordinationNumber",
                         ... ],
``` 

**Note:** See the scope definitions in [Claims and Scopes Specification for the Swedish OpenID Connect Profile](https://www.oidc.se/specifications/swedish-oidc-claims-specification-1_0.html) and [OpenID Connect Claims and Scopes Specification for Sweden Connect](https://docs.swedenconnect.se/technical-framework/latest/OpenID_Connect_Claims_and_Scopes_Specification.html) for a list of which scopes map to which claims.

##### 1.2.2.2. General Entity Categories

Section 6 of [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html#general-entity-categories) defines the `http://id.swedenconnect.se/general-ec/1.0/supports-user-message` entity category.

If this category is assigned to an IdP metadata document, the `https://id.oidc.se/disco/userMessageSupported` parameter MUST be included in the OpenID Connect metadata document. It is also RECOMMENDED to include `https://id.oidc.se/disco/userMessageSupportedMimeTypes`. See Section 3.1 of [Authentication Request Parameter Extensions for the Swedish OpenID Connect Profile](https://www.oidc.se/specifications/request-parameter-extensions-1_1.html#discovery-parameters).

Example:

```json
  "https://id.oidc.se/disco/userMessageSupported" : true,
  "https://id.oidc.se/disco/userMessageSupportedMimeTypes" : [ "text/plain", "text/markdown" ],
  ...
```

<a name="idp-ui-info-mapping"></a>
#### 1.2.3. UI Info Mapping

[Section 1.1.3, UI Info](#ui-info) specifies the translation rules for the `<mdui:UIInfo>` element. For our example above, this would look like:

```json
  "display_name" : "Freja eID+",
  "display_name#sv" : "Freja eID+",
  "display_name#en" : "Freja eID+",
  "description" : "Freja eID är en mobil e-legitimation som gör att du kan logga ...",
  "description#sv" : "Freja eID är en mobil e-legitimation som gör att du kan logga ...",
  "description#en" : "Freja eID is an electronic identity on your mobile that allows you to log in ...",
  "logo_uri" : "https://idp-sweden-connect-valfr-2017.prod.frejaeid.com/idp/images/frejaeid_logo.svg",
```

Note that we add `display_name` and a `description` claim without language tag. This is to enable consumers that do not handle JSON language tags.

Also note that we were only able to add one `logo_uri`.

<a name="idp-organization-mapping"></a>
#### 1.2.4. Organization Mapping

[Section 1.1.4, Organization](#organization) specifies the translation rules for the `<md:Organization>` element. For our example above, this would look like:

```json
  "organization_name" : "Freja eID Group AB",
  "organization_name#sv" : "Freja eID Group AB",
  "organization_name#en" : "Freja eID Group AB",
  "organization_uri" : "https://frejaeid.com",
  "organization_uri#sv" : "https://frejaeid.com",
  "organization_uri#en" : "https://frejaeid.com/en/",
```

<a name="idp-contacts-mapping"></a>
#### 1.2.5. Contacts Mapping

[Section 1.1.5, Contact Persons](#contact-persons) specifies the translation rules for `<md:ContactPerson>` elements. For our example above, this would look like:

```json
  contacts : [ "partnersupport@frejaeid.com" ],
```

<a name="support-for-sign-services"></a>
#### 1.2.6. Support for Sign Services

For Identity Providers that support the `SignMessage` extension (i.e., all IdP:s in Sweden Connect), this support MUST be declared in the OIDC metadata using the scope `https://id.oidc.se/scope/signApproval` (added to `supported_scopes`).

See [Signature Extension for OpenID Connect](https://www.oidc.se/specifications/oidc-signature-extension-1_1.html).

<a name="translation-to-openid-provider-metadata"></a>
#### 1.2.7. Translation to OpenID Provider Metadata

This section illustrates the OP metadata document given the SAML metadata above.

We assume that the service is deployed at `https://freja.example.com`.

```json
{
  "issuer": "https://freja.example.com",

  "authorization_endpoint": "https://freja.example.com/oauth2/authorize",
  "token_endpoint": "https://freja.example.com/oauth2/token",
  "userinfo_endpoint": "https://freja.example.com/oidc/userinfo",
  "jwks_uri": "https://freja.example.com/.well-known/jwks.json",

  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "code_challenge_methods_supported": ["S256"],

  "subject_types_supported": ["public", "pairwise"],

  "id_token_signing_alg_values_supported": 
    ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"],
  "id_token_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256"],
  "id_token_encryption_enc_values_supported": ["A256GCM"],

  "userinfo_signing_alg_values_supported": ["RS256", "PS256", "ES256"],
  "userinfo_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256"],
  "userinfo_encryption_enc_values_supported": ["A256GCM"],

  "request_object_signing_alg_values_supported":
    ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"],
  "request_object_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256"],
  "request_object_encryption_enc_values_supported": ["A256GCM"],

  "token_endpoint_auth_methods_supported": ["private_key_jwt"],
  "token_endpoint_auth_signing_alg_values_supported":
    ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"],

  "claims_parameter_supported": true,
  "request_parameter_supported": true,
  "request_uri_parameter_supported": false,

  "acr_values_supported": [
    "http://id.elegnamnden.se/loa/1.0/loa3",
    "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub"
  ],

  "scopes_supported": [
    "openid",
    "https://id.oidc.se/scope/naturalPersonInfo",
    "https://id.oidc.se/scope/naturalPersonNumber",
    "https://id.oidc.se/scope/signApproval"
  ],

  "claims_supported": [
    "sub",
    "iss",
    "aud",
    "acr",
    "auth_time",
    "txn",
    "iat",
    "exp",
    "nonce",
    "name",
    "given_name",
    "family_name",
    "birthdate",
    "https://id.oidc.se/claim/personalIdentityNumber",
    "https://id.oidc.se/claim/coordinationNumber"
  ],

  "ui_locales_supported": ["sv", "en"],
  "service_documentation": "https://freja.example.com/docs",
  "op_policy_uri": "https://swedenconnect.se/",

  "display_name": "Freja eID+",
  "display_name#sv": "Freja eID+",
  "display_name#en": "Freja eID+",

  "description": "Freja eID är en mobil e-legitimation som gör att du kan logga in, skriva under och godkänna transaktioner hos anslutna tjänster. Den utfärdas i två olika tillitsnivåer, Freja eID Bas och Freja eID+, varav den senare har statliga E-legitimationsnämnden godkänt för kvalitetsmärket Svensk e-legitimation. Med Freja eID+ kan du nå ännu fler tjänster och får även ett ID-Skydd som varnar ifall någon ändrar din folkbokföringsadress hos Skatteverket.",
  "description#sv": "Freja eID är en mobil e-legitimation som gör att du kan logga in, skriva under och godkänna transaktioner hos anslutna tjänster. Den utfärdas i två olika tillitsnivåer, Freja eID Bas och Freja eID+, varav den senare har statliga E-legitimationsnämnden godkänt för kvalitetsmärket Svensk e-legitimation. Med Freja eID+ kan du nå ännu fler tjänster och får även ett ID-Skydd som varnar ifall någon ändrar din folkbokföringsadress hos Skatteverket.",
  "description#en": "Freja eID is an electronic identity on your mobile that allows you to log in, sign and approve transactions. It comes with two levels of identity assurance, basic level and Freja eID+, which is officially approved by the Swedish E-identification board with the quality mark Svensk e-legitimation. Freja eID+ gives you access to more services and a free ID protection, alerting you if your official residential address is changed.",

  "logo_uri": "https://idp-sweden-connect-valfr-2017.prod.frejaeid.com/idp/images/frejaeid_logo.svg",

  "organization_name": "Freja eID Group AB",
  "organization_name#sv": "Freja eID Group AB",
  "organization_name#en": "Freja eID Group AB",
  "organization_uri": "https://frejaeid.com",
  "organization_uri#sv": "https://frejaeid.com",
  "organization_uri#en": "https://frejaeid.com/en/",

  "contacts": ["partnersupport@frejaeid.com"]

}
```

**Note:** Additional OpenID Federation-parameters may be added.

**The JWKS:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "SQC_6Y_QuMN1xE-eOYzqVNxXMXMVkxqnDHHowLNQ9iw",
      "n": "07k07dbynAcWulTN5-C_l0XFz_Csk4_Tdkj8jjRza854XJqxAyIU...e7lZynDzLA5SouIgbE8lc2rpa6RgcLDkO0SRUD1qGDjV0m6EAEzFchAGnSuEGw",
      "e": "AQAB",
      "x5c": [
        "MIIEsTCCAxmgAwIBAgIUWTEky+MBSPqjfMeKBbd2mN2GZ1QwDQYJKoZ...dbflxV++ym8PhDzT7FoV1ClKrm0wrwAXj7qo7RIuiqHpfFRARxH03d2C2glpbU="
      ],
      "x5t#S256": "SQC_6Y_QuMN1xE-eOYzqVNxXMXMVkxqnDHHowLNQ9iw"
    },
    {
      "kty": "RSA",
      "use": "enc",
      "kid": "hoSGx5vhNx_R-1tnL5VtmPX9C5SM3fTINdaMjEtOx9A",
      "n": "wbth_l0iCaZ-awRsFhJbmUq7SsrAA9PlnfJWpcft_yIvzXs_oisq...Bssr03QVtwb-YE1E_AwGkUsAudiCMEq-sLfwIhS9qqttO5ZqmXA--BMg-8xC-Q",
      "e": "AQAB",
      "x5c": [
        "MIIEpDCCAwygAwIBAgIULrzDpxcSdurrOoAjK6ENHpq2JaEwDQYJKoZ...VVNwutmLCfDJOw9O6knb9BDMHFVf+F0NV7iM2zai/LP89JT8wJvI0x5eotfyw=="
      ],
      "x5t#S256": "hoSGx5vhNx_R-1tnL5VtmPX9C5SM3fTINdaMjEtOx9A",
      "alg": "RSA-OAEP"
    }
  ]
}
```

<a name="sp-metadata"></a>
### 1.3. Service Provider Metadata

```xml
<md:EntityDescriptor entityID="http://sandbox.swedenconnect.se/testmyeid">
  <ds:Signature>
    ...
  </ds:Signature>
  <md:Extensions>
    <mdattr:EntityAttributes>
      <saml2:Attribute Name="http://macedir.org/entity-category"
                       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue>http://id.elegnamnden.se/ec/1.0/loa3-pnr</saml2:AttributeValue>
        <saml2:AttributeValue>http://id.swedenconnect.se/ec/sc/uncertified-loa3-pnr</saml2:AttributeValue>
        <saml2:AttributeValue>http://id.elegnamnden.se/ec/1.0/loa4-pnr</saml2:AttributeValue>
        <saml2:AttributeValue>http://id.elegnamnden.se/ec/1.0/eidas-naturalperson</saml2:AttributeValue>
        <saml2:AttributeValue>http://id.swedenconnect.se/ec/1.0/loa3-orgid</saml2:AttributeValue>
        <saml2:AttributeValue>http://id.swedenconnect.se/ec/1.0/loa4-orgid</saml2:AttributeValue>
        <saml2:AttributeValue>http://id.elegnamnden.se/st/1.0/public-sector-sp</saml2:AttributeValue>
        <saml2:AttributeValue>
          http://id.swedenconnect.se/contract/sc/sweden-connect
        </saml2:AttributeValue>
        <saml2:AttributeValue>
          http://id.swedenconnect.se/contract/sc/eid-choice-2017
        </saml2:AttributeValue>
        <saml2:AttributeValue>
          http://id.swedenconnect.se/contract/sc/prepaid-auth-2021
        </saml2:AttributeValue>
        <saml2:AttributeValue>
          http://id.swedenconnect.se/general-ec/1.0/secure-authenticator-binding
        </saml2:AttributeValue>
        <saml2:AttributeValue>
          http://id.swedenconnect.se/general-ec/1.0/accepts-coordination-number
        </saml2:AttributeValue>
      </saml2:Attribute>
    </mdattr:EntityAttributes>
  </md:Extensions>
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="false"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="sv">Testa mitt eID</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">Test my eID</mdui:DisplayName>
        <mdui:Description xml:lang="sv">Applikation för att testa ditt eID</mdui:Description>
        <mdui:Description xml:lang="en">Application for testing your eID</mdui:Description>
        <mdui:Logo height="56" width="280">
          https://eid.idsec.se/testmyeid/images/logo.svg
        </mdui:Logo>
        <mdui:Logo height="256" width="256">
          https://eid.idsec.se/testmyeid/images/logo-notext.svg
        </mdui:Logo>
      </mdui:UIInfo>
    </md:Extensions>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:KeyName>Signing</ds:KeyName>
        <ds:X509Data>
          <ds:X509Certificate>MIIE7DCCAtSgAwIBA...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:KeyName>Encryption</ds:KeyName>
        <ds:X509Data>
          <ds:X509Certificate>MIIE7DCCAtSgAwIBA...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      </md:EncryptionMethod>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      </md:EncryptionMethod>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes192-gcm"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes192-cbc"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="https://eid.idsec.se/testmyeid/saml2/post"
                                 index="0" isDefault="true"/>
    <md:AttributeConsumingService xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
      <md:ServiceName xml:lang="sv">Testa ditt eID</md:ServiceName>
      <md:ServiceName xml:lang="en">Test your eID</md:ServiceName>
      <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3"
                             isRequired="false"/>
      <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.41"
                             isRequired="false"/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="sv">Sweden Connect</md:OrganizationName>
    <md:OrganizationName xml:lang="en">Sweden Connect</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="sv">Sweden Connect</md:OrganizationDisplayName>
    <md:OrganizationDisplayName xml:lang="en">Sweden Connect</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="sv">https://swedenconnect.se</md:OrganizationURL>
    <md:OrganizationURL xml:lang="en">https://swedenconnect.se/en</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="support">
    <md:Company>Sweden Connect</md:Company>
    <md:EmailAddress>operations@swedenconnect.se</md:EmailAddress>
  </md:ContactPerson>
  <md:ContactPerson contactType="technical">
    <md:Company>Sweden Connect</md:Company>
    <md:EmailAddress>operations@swedenconnect.se</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>
```

<a name="sp-entity-categories"></a>
#### 1.3.1. Entity Categories

##### 1.3.1.1. Service Entity Categories

Section 2 of [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html#definitions-for-service-entity-categories) defines a set of Service Entity Categories.

If service entity categories appears in SP metadata they MAY be included in the RP metadata using the `scope` parameter defined in [RFC7591](https://datatracker.ietf.org/doc/html/rfc7591). The mapping is done according to the same table as specified for IdP metadata in [Section 1.2.2.1](#idp-service-entity-categories).

Mapping from XML above (notice that one space-delimited string is used):

```json
  "scope" : "https://id.oidc.se/scope/naturalPersonInfo \
             https://id.oidc.se/scope/naturalPersonNumber \
             https://id.oidc.se/scope/naturalPersonOrgId \
             https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity \
             https://id.swedenconnect.se/scope/eidasSwedishIdentity",
```

Note: This may be useful in cases where an OP needs to know in advance which scopes that may be requested, but is no strict requirement.


##### 1.3.1.2. Service Type Entity Categories

Section 4 of [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html#definitions-for-service-type-entity-categories) defines the following categories:

- `http://id.elegnamnden.se/st/1.0/sigservice` - Indicates that the holder is a SignService. Currently, no mapping exists. In the future we will have to have a clear representation for OIDC. Maybe a trustmark.

- `http://id.elegnamnden.se/st/1.0/public-sector-sp`, `http://id.elegnamnden.se/st/1.0/private-sector-sp` - Indicates that the SP is a public/private sector SP. Relevant for the eIDAS connector. Will be handled with a trustmark.

##### 1.3.1.3. General Entity Categories

Section 6 of [Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html#general-entity-categories) defines the category `http://id.swedenconnect.se/general-ec/1.0/accepts-coordination-number`, which is used within the Sweden Connect SAML federation to indicate support for handling coordination numbers.

In OpenID Connect, a Swedish personal identity number and a coordination number are represented as distinct claims, so there is no need to explicitly signal support for coordination numbers.

<a name="sp-ui-info-mapping"></a>
#### 1.3.2. UI Info Mapping

[Section 1.1.3, UI Info](#ui-info) specifies the translation rules for the `<mdui:UIInfo>` element. For our example above, this would look like:

```json
  "client_name" : "Testa mitt eID",
  "client_name#sv" : "Testa mitt eID",
  "client_name#en" : "Test my eID",
  "display_name" : "Testa mitt eID",
  "display_name#sv" : "Testa mitt eID",
  "display_name#en" : "Test my eID",
  "description" : "Applikation för att testa ditt eID",
  "description#sv" : "Applikation för att testa ditt eID",
  "description#en" : "Application for testing your eID",
  "logo_uri" : "https://eid.idsec.se/testmyeid/images/logo.svg",
```

1. We included both `client_name` and `display_name`, which represent the same information. The reason is that `client_name` is defined in [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html) and is widely supported, whereas `display_name` is defined in [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html#name-informational-metadata-exte) but currently has limited implementation support.

2. We added `display_name` and `description` without language tags. This enables consumption by systems that do not support JSON language tags.

3. We were only able to include a single `logo_uri`.

<a name="sp-organization-mapping"></a>
#### 1.3.3. Organization Mapping

[Section 1.1.4, Organization](#organization) specifies the translation rules for the `<md:Organization>` element. For our example above, this would look like:

```json
  "organization_name" : "Sweden Connect",
  "organization_name#sv" : "Sweden Connect",
  "organization_name#en" : "Sweden Connect",
  "organization_uri" : "https://swedenconnect.se",
  "organization_uri#sv" : "https://swedenconnect.se",
  "organization_uri#en" : "https://swedenconnect.se/en",
```

<a name="sp-contacts-mapping"></a>
#### 1.3.4. Contacts Mapping

[Section 1.1.5, Contact Persons](#contact-persons) specifies the translation rules for `<md:ContactPerson>` elements. For our example above, this would look like:

```json
  contacts : [ "operations@swedenconnect.se" ],
```

<a name="translation-to-oidc-relying-party-metadata"></a>
#### 1.3.5. Translation to OIDC Relying Party Metadata

This section illustrates the OIDC Relying Party metadata given the SAML metadata above.

```json
{
  "client_name": "Testa mitt eID",
  "client_name#sv": "Testa mitt eID",
  "client_name#en": "Test my eID",

  "display_name": "Testa mitt eID",
  "display_name#sv": "Testa mitt eID",
  "display_name#en": "Test my eID",

  "description": "Applikation för att testa ditt eID",
  "description#sv": "Applikation för att testa ditt eID",
  "description#en": "Application for testing your eID",

  "logo_uri": "https://eid.idsec.se/testmyeid/images/logo.svg",

  "organization_name": "Sweden Connect",
  "organization_name#sv": "Sweden Connect",
  "organization_name#en": "Sweden Connect",
  "organization_uri": "https://swedenconnect.se",
  "organization_uri#sv": "https://swedenconnect.se",
  "organization_uri#en": "https://swedenconnect.se",

  "contacts": ["operations@swedenconnect.se"],

  "scope": "https://id.oidc.se/scope/naturalPersonInfo https://id.oidc.se/scope/naturalPersonNumber https://id.oidc.se/scope/naturalPersonOrgId https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity https://id.swedenconnect.se/scope/eidasSwedishIdentity",

  "redirect_uris": ["https://testmyeid.example.com/oidc/callback"],

  "response_types": ["code"],
  "grant_types": ["authorization_code"],
  "subject_type": "public",
  "default_acr_values": ["http://id.elegnamnden.se/loa/1.0/loa3"],

  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "RS256",

  "request_object_signing_alg": "RS256",

  "id_token_signed_response_alg": "RS256",
  "id_token_encrypted_response_alg": "RSA-OAEP",
  "id_token_encrypted_response_enc": "A256GCM",

  "userinfo_encrypted_response_alg": "RSA-OAEP",
  "userinfo_encrypted_response_enc": "A256GCM",

  "jwks": {
    "keys": [
      {
        "kty": "RSA",
        "use": "sig",
        "kid": "Signing",
        "alg": "RS256",
        "n": "r...<base64url modulus>...",
        "e": "AQAB",
        "x5c": [
          "MIIE7DCCAtSgAwIBAgIEWv...oIRazyQ=="
        ],
        "x5t#S256": "…sha256-thumbprint-of-cert…"
      },
      {
        "kty": "RSA",
        "use": "enc",
        "kid": "Encryption",
        "alg": "RSA-OAEP",
        "n": "v...<base64url modulus>...",
        "e": "AQAB",
        "x5c": [
          "MIIE7DCCA...EpbQAw=="
        ],
        "x5t#S256": "…sha256-thumbprint-of-cert…"
      }
    ]
  }
}
```

**Note:** Additional OpenID Federation-parameters may be added.

<a name="openid-connect-to-saml"></a>
## 2. OpenID Connect to SAML

> TODO
