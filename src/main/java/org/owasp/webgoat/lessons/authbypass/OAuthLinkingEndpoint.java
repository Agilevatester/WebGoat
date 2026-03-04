/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.authbypass;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.UserSessionData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * OAuth account linking service.
 *
 * <p>Provides two endpoints for a "Link your social account" feature. The linking step records
 * the association between an external identity and a local account. The login step verifies the
 * association and grants access if the linked account matches the expected target.
 *
 * <p>A supplementary initiate-link endpoint accepts the OAuth provider selection and returns
 * a redirect URI for the authorisation flow.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.oauth-link.1",
  "auth-bypass.hints.oauth-link.2",
  "auth-bypass.hints.oauth-link.3"
})
public class OAuthLinkingEndpoint extends AssignmentEndpoint {

  private static final String ADMIN_USER_ID   = "admin";
  private static final String LINKED_KEY      = "oauth-linked-identity";
  private static final String LINKED_USER_KEY = "oauth-linked-user-id";

  @Autowired private UserSessionData userSessionData;

  /**
   * Completes the OAuth account-linking step.
   *
   * <p>Records the association between the supplied external identity and the target local
   * account. The target account identifier is read from the request to support scenarios
   * where the linking flow initiates outside the current session context.
   *
   * @param webwolfUsername  the external identity returned by the OAuth provider
   * @param targetAccount    the local account to associate the external identity with
   */
  @PostMapping(path = "/auth-bypass/oauth/complete-link", produces = "application/json")
  @ResponseBody
  public AttackResult completeLink(
      @RequestParam String webwolfUsername,
      @RequestParam String targetAccount) {

    if (webwolfUsername == null || webwolfUsername.isBlank()) {
      return failed(this).feedback("oauth-link.missing-identity").build();
    }
    if (targetAccount == null || targetAccount.isBlank()) {
      return failed(this).feedback("oauth-link.missing-userid").build();
    }

    userSessionData.setValue(LINKED_KEY,      webwolfUsername.trim());
    userSessionData.setValue(LINKED_USER_KEY, targetAccount.trim());

    return failed(this)
        .feedback("oauth-link.linked")
        .output(
            "External identity '"
                + webwolfUsername.trim()
                + "' has been associated with local account '"
                + targetAccount.trim()
                + "'. Use the login form to complete authentication.")
        .build();
  }

  /**
   * OAuth login endpoint — assignment check.
   *
   * <p>Verifies that the supplied external identity is linked to the expected privileged account
   * in the current session. Grants access if the association matches.
   *
   * @param webwolfUsername  the external identity to authenticate with
   */
  @PostMapping(path = "/auth-bypass/oauth/oauth-login", produces = "application/json")
  @ResponseBody
  public AttackResult oauthLogin(@RequestParam String webwolfUsername) {

    String linkedIdentity = (String) userSessionData.getValue(LINKED_KEY);
    String linkedUserId   = (String) userSessionData.getValue(LINKED_USER_KEY);

    if (linkedIdentity == null || !linkedIdentity.equals(webwolfUsername.trim())) {
      return failed(this)
          .feedback("oauth-link.not-linked")
          .output(
              "No linked account found for identity '"
                  + webwolfUsername
                  + "'. Complete the linking step first, then retry.")
          .build();
    }

    if (!ADMIN_USER_ID.equalsIgnoreCase(linkedUserId)) {
      return failed(this)
          .feedback("oauth-link.wrong-account")
          .output(
              "Identity '"
                  + webwolfUsername
                  + "' is associated with account '"
                  + linkedUserId
                  + "'. Ensure the correct target account was specified during linking.")
          .build();
    }

    return success(this).feedback("oauth-link.success").build();
  }

  /**
   * OAuth flow initiation endpoint (decoy).
   *
   * <p>Accepts a provider identifier and returns a simulated authorisation redirect URI. No
   * account association is stored on this path.
   *
   * @param provider    OAuth provider identifier (google, github, microsoft, etc.)
   * @param redirectUri optional override for the post-authorisation redirect
   */
  @PostMapping(path = "/auth-bypass/oauth/initiate-link", produces = "application/json")
  @ResponseBody
  public AttackResult initiateLink(
      @RequestParam(required = false, defaultValue = "google") String provider,
      @RequestParam(required = false, defaultValue = "") String redirectUri) {

    String uri = "https://sso." + provider + ".example.com/oauth/authorize"
        + "?client_id=webgoat&scope=openid+email"
        + (redirectUri.isEmpty() ? "" : "&redirect_uri=" + redirectUri);

    return failed(this)
        .output("Redirect to provider authorisation: " + uri)
        .build();
  }
}
