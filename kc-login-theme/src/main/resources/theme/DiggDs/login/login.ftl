<#--
  DIGG discovery-service style login page: a language switcher and the full DIGG logo in the
  card's top bar, title/tab typography and button styling (size, radius, shadow, weight) matched
  to a reference design, and the identity providers split into two TABS instead of a top list plus
  a collapsible badge.

  Identity providers are split into two groups by alias:
    - "Legitimering" — personal e-identification (e.g. BankID, foreign eID)
    - "Tjänstelegitimation" — e-service credentials (SITHS, eFos, Freja eID Org)
  Each tab is shown only when it has at least one matching provider; if only one group has
  providers, only that tab is shown. If neither group has providers, no tabs are shown at all.

  Tabs are built with the classic hidden-radio-button + <label> technique (no JavaScript), the
  same no-JS principle the rest of this theme follows. The language switcher is a single globe
  icon that links directly to the other configured locale — no dropdown, since there are only
  ever two. No provider logos are shown; every entry is text only.
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

<#macro cardTopbar>
    <div class="ds-card-topbar">
        <#if realm.internationalizationEnabled?? && realm.internationalizationEnabled && locale?? && locale.supported?? && (locale.supported?size > 1)>
            <#-- Property names (locale.current, locale.supported[].label/.url) follow Keycloak's
                 published keycloak.v2 template.ftl; verify against the running 26.7.3 instance,
                 since that base template is not vendored in this repo. No dropdown: the globe is
                 itself a direct link to the other configured locale, found below. -->
            <#assign otherLocaleUrl = "">
            <#list locale.supported as l>
                <#if l.label != locale.current && otherLocaleUrl == "">
                    <#assign otherLocaleUrl = l.url>
                </#if>
            </#list>
            <#if otherLocaleUrl != "">
                <a class="ds-lang-toggle" href="${otherLocaleUrl}" aria-label="${msg("scChangeLanguage")}">
                    <svg class="ds-lang-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                        <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/>
                        <ellipse cx="12" cy="12" rx="4" ry="9" fill="none" stroke="currentColor" stroke-width="1.5"/>
                        <line x1="3" y1="12" x2="21" y2="12" stroke="currentColor" stroke-width="1.5"/>
                    </svg>
                </a>
            </#if>
        </#if>
        <img class="ds-card-logo" src="${url.resourcesPath}/img/digg-logo.svg" alt="Myndigheten för digital förvaltning">
    </div>
</#macro>

<@layout.registrationLayout displayMessage=true displayInfo=false; section>
<!-- template: login.ftl (digg-ds) -->

    <#if section = "header">
        <@cardTopbar />
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
