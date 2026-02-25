// need custom js for this?

webgoat.customjs.onBypassResponse = function(data) {
    webgoat.customjs.jquery('#verify-account-form').hide();
    webgoat.customjs.jquery('#change-password-form').show();
}

webgoat.customjs.on2FABypassResponse = function(data) {
    webgoat.customjs.jquery('#2fa-verify-form').hide();
}

// MFA State Skip callbacks

webgoat.customjs.prepareMfaStep1Json = function() {
    var $ = webgoat.customjs.jquery;
    var $form = $('#mfa-step1-form');
    return JSON.stringify({
        username: $form.find('[name="username"]').val(),
        password: $form.find('[name="password"]').val()
    });
}

webgoat.customjs.prepareMfaOtpJson = function() {
    var $ = webgoat.customjs.jquery;
    var $form = $('#mfa-otp-form');
    return JSON.stringify({
        otp: $form.find('[name="otp"]').val()
    });
}

webgoat.customjs.prepareMfaAccessJson = function() {
    // POST {} so the endpoint consistently uses JSON
    return JSON.stringify({});
}

webgoat.customjs.onMfaStep1Response = function(data) {
    console.log("MFA Step 1 Response: :", data);
    var outText = $('.attack-container:has(#mfa-step1-form) .attack-output').text() || '';
    if (outText.indexOf('MFA_STATE_SKIP:STEP1_OK') === -1) {
        return;
    }
    webgoat.customjs.jquery('#mfa-step1-form').hide();
    webgoat.customjs.jquery('#mfa-otp-form').show();
    webgoat.customjs.jquery('#mfa-access-form').show();
}

webgoat.customjs.onMfaOtpResponse = function(data) {
    // Keep both Step 2 and Step 3 visible. Step 3 should be reachable even if Step 2 is skipped.
}

webgoat.customjs.onMfaAccessResponse = function(data) {
    webgoat.customjs.jquery('#mfa-access-form').hide();
}

// MFA OTP Leak callbacks
webgoat.customjs.onMfaSendOtpResponse = function(data) {
    webgoat.customjs.jquery('#mfa-send-otp-form').hide();
    webgoat.customjs.jquery('#mfa-verify-otp-form').show();
}

webgoat.customjs.onMfaVerifyOtpResponse = function(data) {
    webgoat.customjs.jquery('#mfa-verify-otp-form').hide();
}

webgoat.customjs.onMissingAuthResponse = function(data) {
    webgoat.customjs.jquery('#missing-auth-form').hide();
}

webgoat.customjs.onRateLimitResponse = function(data) {
    webgoat.customjs.jquery('#brute-login-form').hide();
}

webgoat.customjs.onPathBypassResponse = function(data) {
    webgoat.customjs.jquery('#path-bypass-form').hide();
}

// Technique 3 — Brute Force
webgoat.customjs.onMfaBruteforceResponse = function(data) {
    webgoat.customjs.jquery('#mfa-bruteforce-form').hide();
}

// Technique 4 — Recovery Flow Bypass
webgoat.customjs.onMfaRecoveryStep1Response = function(data) {
    webgoat.customjs.jquery('#mfa-recovery-step1-form').hide();
    webgoat.customjs.jquery('#mfa-recovery-step2-form').show();
}

webgoat.customjs.onMfaRecoveryStep2Response = function(data) {
    // Keep the recovery bypass form always visible
}

webgoat.customjs.onMfaRecoveryBypassResponse = function(data) {
    webgoat.customjs.jquery('#mfa-recovery-bypass-form').hide();
}

// Technique 5 — Backup Code Abuse
webgoat.customjs.onMfaRevealCodesResponse = function(data) {
    webgoat.customjs.jquery('#mfa-reveal-codes-form').hide();
    webgoat.customjs.jquery('#mfa-backup-login-form').show();
}

webgoat.customjs.onMfaBackupLoginResponse = function(data) {
    webgoat.customjs.jquery('#mfa-backup-login-form').hide();
}

// Technique 10 — Client-Side Trust
webgoat.customjs.onMfaClientTrustResponse = function(data) {
    webgoat.customjs.jquery('#mfa-client-trust-form').hide();
}

// Technique 9 — OAuth Account Linking Pitfall
webgoat.customjs.onOAuthLinkResponse = function(data) {
    // Show the login form once a link is established
    webgoat.customjs.jquery('#oauth-login-form').show();
}

webgoat.customjs.onOAuthLoginResponse = function(data) {
    webgoat.customjs.jquery('#oauth-login-form').hide();
}

var onViewProfile = function () {
    console.warn("on view profile activated")
    webgoat.customjs.jquery.ajax({
        method: "GET",
        url: "IDOR/profile",
        contentType: 'application/json; charset=UTF-8'
     }).then(webgoat.customjs.idorViewProfile);
}

