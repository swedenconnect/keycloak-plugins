<#--
  DIGG discovery-service style login page, with a password form behind a toggle.

  Combines the identity-provider-first layout of SwedenconnectIdpPsw (identity providers as
  buttons, username/password form folded behind a last toggle card) with the DIGG discovery-service
  visual style and per-provider icon matching of DiggDs.

  The form is open from the start when there is no identity provider, and after a failed login, so
  that the error message is never hidden behind a closed toggle. The toggle is a native <details>
  element, so it needs no JavaScript and is operable from the keyboard.

  Each identity-provider card gets a brand icon by matching its alias against a known pattern, e.g.
  an alias that contains "bankid" gets the BankID logo. A provider whose alias matches none of the
  patterns falls back to a generic icon, so a newly added identity provider never breaks the page.
-->
<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#import "passkeys.ftl" as passkeys>

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
        <#assign hasProviders = social.providers?? && social.providers?has_content>
        <#assign hasLoginError = messagesPerField.existsError('username','password')>

        <#if hasProviders>
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

        <#if realm.password>
            <div id="kc-form">
                <div id="kc-form-wrapper">
                    <#if hasProviders>
                        <details id="ds-password-login" class="ds-password-login"<#if hasLoginError> open</#if>>
                            <summary class="ds-selection-block ds-password-toggle">
                                <span class="ds-selection-title">${msg("scUsernamePassword")}</span>
                            </summary>
                            <div class="ds-password-login-body">
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
