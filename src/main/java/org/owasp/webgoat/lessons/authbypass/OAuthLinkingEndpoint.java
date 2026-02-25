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
 * OAuth Account Linking Pitfall — Technique 9 (DeepStrike).
 *
 * <p>Demonstrates an insecure "Link your social account" feature. The server exposes two endpoints:
 *
 * <ol>
 *   <li>{@code POST /auth-bypass/oauth/complete-link} — accepts a {@code webwolfUsername} (the
 *       OAuth identity returned by the provider) and a {@code userId} (whose local account to link
 *       it to). <b>VULNERABILITY:</b> {@code userId} is read from the request body rather than from
 *       the authenticated server-side session. Any caller can therefore set {@code userId=admin} and
 *       link their own WebWolf identity to the admin account.
 *   <li>{@code POST /auth-bypass/oauth/oauth-login} — the assignment endpoint. Checks whether the
 *       supplied {@code webwolfUsername} is linked to the admin account in the current session. If
 *       so, access is granted and the lesson is marked complete.
 * </ol>
 *
 * <p><b>Correct implementation:</b> the {@code userId} that is linked must always come from the
 * authenticated session ({@code session.getAttribute("currentUserId")}), never from a
 * client-supplied request parameter or from the OAuth {@code state} parameter that the client can
 * tamper with before the callback is processed.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.oauth-link.1",
  "auth-bypass.hints.oauth-link.2",
  "auth-bypass.hints.oauth-link.3"
})
public class OAuthLinkingEndpoint extends AssignmentEndpoint {

  static final String ADMIN_USER_ID = "admin";
  static final String LINKED_KEY = "oauth-linked-identity";
  static final String LINKED_USER_KEY = "oauth-linked-user-id";

  @Autowired private UserSessionData userSessionData;

  /**
   * Simulates the OAuth callback / account-linking step.
   *
   * <p>A legitimate server would read the target account identifier from the authenticated session
   * (set during the {@code /initiate} step). This implementation reads it from a request parameter
   * — allowing the caller to specify any {@code userId}, including {@code "admin"}.
   *
   * @param webwolfUsername the identity returned by the mock OAuth provider (WebWolfSSO)
   * @param userId the local account to link the OAuth identity to — VULNERABILITY: client-supplied
   */
  @PostMapping(path = "/auth-bypass/oauth/complete-link", produces = "application/json")
  @ResponseBody
  public AttackResult completeLink(
      @RequestParam String webwolfUsername, @RequestParam String userId) {

    if (webwolfUsername == null || webwolfUsername.isBlank()) {
      return failed(this).feedback("oauth-link.missing-identity").build();
    }
    if (userId == null || userId.isBlank()) {
      return failed(this).feedback("oauth-link.missing-userid").build();
    }

    // VULNERABILITY: userId comes directly from the request — the client decides whose account to
    // link. A correct implementation would use session.getAttribute("initiatingUserId") here.
    userSessionData.setValue(LINKED_KEY, webwolfUsername.trim());
    userSessionData.setValue(LINKED_USER_KEY, userId.trim());

    return failed(this)
        .feedback("oauth-link.linked")
        .output(
            "WebWolfSSO identity '"
                + webwolfUsername.trim()
                + "' is now linked to local account '"
                + userId.trim()
                + "'. "
                + "If you set userId=admin you can now log in via the OAuth Login form below.")
        .build();
  }

  /**
   * Assignment endpoint — grants access if the supplied WebWolf identity is linked to the admin
   * account.
   */
  @PostMapping(path = "/auth-bypass/oauth/oauth-login", produces = "application/json")
  @ResponseBody
  public AttackResult oauthLogin(@RequestParam String webwolfUsername) {

    String linkedIdentity = (String) userSessionData.getValue(LINKED_KEY);
    String linkedUserId = (String) userSessionData.getValue(LINKED_USER_KEY);

    if (linkedIdentity == null || !linkedIdentity.equals(webwolfUsername.trim())) {
      return failed(this)
          .feedback("oauth-link.not-linked")
          .output(
              "No link found for WebWolf identity '"
                  + webwolfUsername
                  + "'. "
                  + "Use the 'Complete Link' form first, then try again.")
          .build();
    }

    if (!ADMIN_USER_ID.equalsIgnoreCase(linkedUserId)) {
      return failed(this)
          .feedback("oauth-link.wrong-account")
          .output(
              "Identity '"
                  + webwolfUsername
                  + "' is linked to account '"
                  + linkedUserId
                  + "', not admin. "
                  + "Repeat the linking step with userId=admin.")
          .build();
    }

    return success(this).feedback("oauth-link.success").build();
  }
}
