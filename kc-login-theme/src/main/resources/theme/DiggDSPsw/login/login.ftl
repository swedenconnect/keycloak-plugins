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

  The username/password form is only ever offered under "Legitimering" (as a badge at the bottom
  of that tab's panel), never under "Tjänstelegitimation" — a password fallback doesn't belong
  next to strict organisational credentials. If the realm has no identity providers at all, the
  form is shown directly instead, with no tabs or badge to unfold.

  Tabs and the password badge are built with the hidden-radio/checkbox + <label> technique (no
  JavaScript), the same no-JS principle the rest of this theme follows. No provider logos are
  shown; every entry is text only.
-->
<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#import "passkeys.ftl" as passkeys>

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

<#macro passwordForm autofocus>
    <form id="kc-form-login" class="${properties.kcFormClass!}" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post" novalidate="novalidate">
        <#if !usernameHidden??>
            <#assign label>
                <#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>
            </#assign>
            <@field.input name="username" label=label error=messagesPerField.getFirstError('username','password')
                autofocus=autofocus autocomplete="${(enableWebAuthnConditionalUI?has_content)?then('username webauthn', 'username')}" value=login.username!'' />
            <@field.password name="password" label=msg("password") error="" forgotPassword=realm.resetPasswordAllowed autofocus=usernameHidden?? autocomplete="current-password">
                <#if realm.rememberMe && !usernameHidden??>
                    <@field.checkbox name="rememberMe" label=msg("rememberMe") value=login.rememberMe?? />
                </#if>
            </@field.password>
        <#else>
            <@field.password name="password" label=msg("password") forgotPassword=realm.resetPasswordAllowed autofocus=usernameHidden?? autocomplete="current-password">
                <#if realm.rememberMe && !usernameHidden??>
                    <@field.checkbox name="rememberMe" label=msg("rememberMe") value=login.rememberMe?? />
                </#if>
            </@field.password>
        </#if>

        <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
        <@buttons.loginButton />
    </form>
</#macro>

<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
<!-- template: login.ftl (digg-ds-psw) -->

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
        <#assign hasAnyTabs = hasPersonalProviders || hasServiceProviders>
        <#assign hasLoginError = messagesPerField.existsError('username','password')>

        <#-- Username/password is only ever offered under "Legitimering", never under
             "Tjänstelegitimation" — a password fallback doesn't belong next to strict
             organisational credentials (SITHS/eFos/Freja eID Org). -->
        <#if hasAnyTabs>
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
                        <#if realm.password>
                            <div id="kc-form" class="ds-password-section">
                                <div id="kc-form-wrapper">
                                    <details id="ds-password-login" class="ds-toggle-card"<#if hasLoginError> open</#if>>
                                        <summary class="ds-selection-block ds-toggle-summary">
                                            <span class="ds-selection-title">${msg("scUsernamePassword")}</span>
                                        </summary>
                                        <div class="ds-toggle-body">
                                            <@passwordForm autofocus=hasLoginError />
                                        </div>
                                    </details>
                                </div>
                            </div>
                            <@passkeys.conditionalUIData />
                        </#if>
                    </div>
                </#if>
                <#if hasServiceProviders>
                    <div class="ds-tab-panel" id="ds-panel-tjanstelegitimation">
                        <@idpList serviceProviders />
                    </div>
                </#if>
            </div>
        <#elseif realm.password>
            <div id="kc-form" class="ds-password-section">
                <div id="kc-form-wrapper">
                    <@passwordForm autofocus=true />
                </div>
            </div>
            <@passkeys.conditionalUIData />
        </#if>
    <#elseif section = "info" >
        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
            <div id="kc-registration-container">
                <div id="kc-registration">
                    <span>${msg("noAccount")} <a href="${url.registrationUrl}">${msg("doRegister")}</a></span>
                </div>
            </div>
        </#if>
    </#if>

</@layout.registrationLayout>
