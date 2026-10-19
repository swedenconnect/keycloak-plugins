<#--
  DIGG discovery-service style login page: title/tab typography and button styling (size, radius,
  shadow, weight) matched to a reference design, and the identity providers split into two TABS
  instead of a top list plus a collapsible badge. The DIGG logo and the language switcher are not
  rendered here but by this theme's template.ftl, so that every page shows them.

  Identity providers are split into two groups by alias:
    - "Legitimering" — personal e-identification (e.g. BankID, foreign eID)
    - "Tjänstelegitimation" — e-service credentials (SITHS, eFos, Freja eID Org)
  Each tab is shown only when it has at least one matching provider; if only one group has
  providers, only that tab is shown. If neither group has providers, no tabs are shown at all.

  Tabs are built with the classic hidden-radio-button + <label> technique (no JavaScript), the
  same no-JS principle the rest of this theme follows. No provider logos are shown; every entry is
  text only.
-->
<#import "template.ftl" as layout>

<#function isServiceIdp alias>
    <#local a = (alias!"")?lower_case>
    <#return a?contains("siths") || a?contains("efos") || a?contains("frejaorg")>
</#function>

<#macro idpList providers>
    <ul class="ds-idp-list">
        <#list providers as p>
            <li>
                <a data-once-link data-disabled-class="${properties.kcFormSocialAccountListButtonDisabledClass!}"
                   id="social-${p.alias}" class="ds-selection-block" href="${p.loginUrl}">
                    <span class="ds-selection-title">${p.displayName!}</span>
                </a>
            </li>
        </#list>
    </ul>
</#macro>

<@layout.registrationLayout displayMessage=true displayInfo=false; section>
<!-- template: login.ftl (digg-ds) -->

    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">
        <#assign personalProviders = []>
        <#assign serviceProviders = []>
        <#if social.providers?? && social.providers?has_content>
            <#list social.providers as p>
                <#if isServiceIdp(p.alias!"")>
                    <#assign serviceProviders = serviceProviders + [p]>
                <#else>
                    <#assign personalProviders = personalProviders + [p]>
                </#if>
            </#list>
        </#if>
        <#assign hasPersonalProviders = personalProviders?has_content>
        <#assign hasServiceProviders = serviceProviders?has_content>

        <#if hasPersonalProviders || hasServiceProviders>
            <div class="ds-tabs">
                <#if hasPersonalProviders>
                    <input type="radio" name="ds-tabs" id="ds-tab-legitimering" class="ds-tab-input" checked>
                </#if>
                <#if hasServiceProviders>
                    <input type="radio" name="ds-tabs" id="ds-tab-tjanstelegitimation" class="ds-tab-input"<#if !hasPersonalProviders> checked</#if>>
                </#if>
                <div class="ds-tab-labels">
                    <#if hasPersonalProviders>
                        <label for="ds-tab-legitimering" class="ds-tab-label">${msg("scLegitimering")}</label>
                    </#if>
                    <#if hasServiceProviders>
                        <label for="ds-tab-tjanstelegitimation" class="ds-tab-label">${msg("scServiceIdp")}</label>
                    </#if>
                </div>
                <#if hasPersonalProviders>
                    <div class="ds-tab-panel" id="ds-panel-legitimering">
                        <@idpList personalProviders />
                    </div>
                </#if>
                <#if hasServiceProviders>
                    <div class="ds-tab-panel" id="ds-panel-tjanstelegitimation">
                        <@idpList serviceProviders />
                    </div>
                </#if>
            </div>
        </#if>
    </#if>

</@layout.registrationLayout>
