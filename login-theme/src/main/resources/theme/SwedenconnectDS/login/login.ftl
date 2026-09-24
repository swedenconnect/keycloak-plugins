<#--
  Sweden Connect discovery-service login page.

  Identity-provider selection only, no username/password form at all: a pure list of identity
  providers, styled the same as the SwedenconnectIdpPsw theme's identity-provider buttons (see
  swedenconnect-ds.css). Differs from that theme by giving each provider a brand icon, chosen by
  matching its alias against a known pattern, e.g. an alias that contains "bankid" gets the BankID
  logo. A provider whose alias matches none of the patterns falls back to a generic icon, so a newly
  added identity provider never breaks the page.
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
<!-- template: login.ftl (swedenconnect-ds) -->

    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">
        <#assign hasProviders = social.providers?? && social.providers?has_content>

        <#if hasProviders>
            <p class="sc-subtitle">${msg("scSelectIdp")}</p>
            <ul id="kc-social-providers" class="sc-idp-list">
                <#list social.providers as p>
                    <li>
                        <a data-once-link data-disabled-class="${properties.kcFormSocialAccountListButtonDisabledClass!}"
                           id="social-${p.alias}" class="sc-btn sc-btn-filled sc-btn-icon" href="${p.loginUrl}">
                            <img alt="" class="sc-btn-icon-img" src="${url.resourcesPath}/img/idp/${idpIconFile(p.alias!"")}">
                            <span class="sc-btn-title">${p.displayName!}</span>
                        </a>
                    </li>
                </#list>
            </ul>
        </#if>
    </#if>

</@layout.registrationLayout>
