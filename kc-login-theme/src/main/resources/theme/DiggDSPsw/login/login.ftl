<#--
  DIGG discovery-service style login page, with a password form and grouped e-service credentials
  behind toggle badges.

  Identity providers are split into two groups by alias:
    - personal e-identification (e.g. BankID, foreign eID) — listed directly at the top
    - e-service credentials (SITHS, eFos, Freja eID Org) — behind the "E-tjänste legitimation" badge,
      shown only when the realm has at least one such provider configured
  The password form sits behind its own "Användarnamn Lösenord" badge, unless there are no identity
  providers at all, in which case it is shown directly with no badge to unfold.

  Both badges are native <details> elements, so they need no JavaScript and are operable from the
  keyboard. No provider logos are shown; every entry is text only.
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
        <#assign hasAnyProviders = hasPersonalProviders || hasServiceProviders>
        <#assign hasLoginError = messagesPerField.existsError('username','password')>

        <#if hasAnyProviders>
            <p class="ds-subtitle">${msg("scSelectIdp")}</p>
        </#if>

        <#if hasPersonalProviders>
            <@idpList personalProviders />
        </#if>

        <#if hasServiceProviders>
            <details id="ds-service-idp" class="ds-toggle-card">
                <summary class="ds-selection-block ds-toggle-summary">
                    <span class="ds-selection-title">${msg("scServiceIdp")}</span>
                </summary>
                <div class="ds-toggle-body">
                    <@idpList serviceProviders />
                </div>
            </details>
        </#if>

        <#if realm.password>
            <div id="kc-form" class="ds-password-section">
                <div id="kc-form-wrapper">
                    <#if hasAnyProviders>
                        <details id="ds-password-login" class="ds-toggle-card"<#if hasLoginError> open</#if>>
                            <summary class="ds-selection-block ds-toggle-summary">
                                <span class="ds-selection-title">${msg("scUsernamePassword")}</span>
                            </summary>
                            <div class="ds-toggle-body">
                                <@passwordForm autofocus=hasLoginError />
                            </div>
                        </details>
                    <#else>
                        <@passwordForm autofocus=true />
                    </#if>
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
