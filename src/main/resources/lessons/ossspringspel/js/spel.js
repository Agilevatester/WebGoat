// SpEL injection lesson callbacks

webgoat.customjs.onSpelSearchResponse = function(data) {
    // Search result stays visible so students can read the SpEL evaluation output.
    // No form hiding — students iterate on payloads multiple times.
}

webgoat.customjs.onSpelTokenResponse = function(data) {
    webgoat.customjs.jquery('#spel-token-form').hide();
}
