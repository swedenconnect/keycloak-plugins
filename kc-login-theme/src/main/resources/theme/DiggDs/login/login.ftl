<#--
  DIGG discovery-service style login page.

  Differs from the keycloak.v2 login.ftl, and from the SwedenconnectIdpPsw theme, in that there is
  no username/password form at all: only the list of identity providers, styled after DIGG's own
  discovery service at https://iam.digg.se/ds.

  Each provider gets a brand icon by matching its alias against a known pattern, e.g. an alias that
  contains "bankid" gets the BankID logo. A provider whose alias matches none of the patterns falls
  back to a generic icon, so a newly added identity provider never breaks the page.
-->
<#import "template.ftl" as layout>

<#function idpIconFile alias>
    <#local a = (alias!"")?lower_case>
    <#if a?contains("bankid")>
        <#return "bankid.svg">
    </#if>
    <#if a?contains("siths")>
        <#return "siths.svg">
    </#if>
    <#if a?contains("efos")>
        <#return "efos.png">
    </#if>
    <#if a?contains("freja")>
        <#return "freja.svg">
    </#if>
    <#if a?contains("eidas") || a?contains("foreign")>
        <#return "foreign-eid.svg">
    </#if>
    <#return "default.svg">
</#function>

<@layout.registrationLayout displayMessage=true displayInfo=false; section>
<!-- template: login.ftl (digg-ds) -->

    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">
        <#assign hasProviders = social.providers?? && social.providers?has_content>

        <#if hasProviders>
            <p class="ds-subtitle">${msg("scSelectIdp")}</p>
            <ul id="kc-social-providers" class="ds-idp-list">
                <#list social.providers as p>
                    <li>
                        <a data-once-link data-disabled-class="${properties.kcFormSocialAccountListButtonDisabledClass!}"
                           id="social-${p.alias}" class="ds-selection-block" href="${p.loginUrl}">
                            <img alt="" class="ds-selection-logo" src="${url.resourcesPath}/img/idp/${idpIconFile(p.alias!"")}">
                            <span class="ds-selection-title">${p.displayName!}</span>
                        </a>
                    </li>
                </#list>
            </ul>
        </#if>
    </#if>

</@layout.registrationLayout>
