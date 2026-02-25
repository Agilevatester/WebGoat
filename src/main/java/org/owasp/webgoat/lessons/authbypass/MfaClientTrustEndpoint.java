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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * MFA Client-Side Trust / Response Manipulation — Technique 10 (DeepStrike).
 *
 * <p>Demonstrates a server that delegates the MFA completion decision to the client. The
 * authentication form includes a hidden field {@code mfaVerified} initialised to {@code false}.
 * The server reads this field and grants access if it is {@code true}.
 *
 * <p>This simulates the real-world pattern where a frontend makes an OTP verification API call,
 * receives {@code "success": false} on failure, and is supposed to block the login. A developer
 * trying to "save an extra round-trip" shortcutted the flow by having the client post
 * {@code mfaVerified=true} directly to the login endpoint when the OTP check passes — but never
 * validated the value server-side (since "the client already checked it").
 *
 * <p>The fix is trivially obvious: the server must be the sole authority on authentication state.
 * Never accept authorisation decisions from the client.
 *
 * <p>Students discover the hidden {@code mfaVerified} field in the form (DevTools → Elements),
 * change its value from {@code false} to {@code true}, and submit. Valid credentials are required
 * but the MFA check is bypassed by the parameter value alone.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.mfa-client-trust.1",
  "auth-bypass.hints.mfa-client-trust.2",
  "auth-bypass.hints.mfa-client-trust.3"
})
public class MfaClientTrustEndpoint extends AssignmentEndpoint {

  static final String VALID_USER = "admin";
  static final String VALID_PASS = "password123";

  @PostMapping(
      path = "/auth-bypass/mfa/client-trust-login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult login(
      @RequestParam String username,
      @RequestParam String password,
      @RequestParam(defaultValue = "false") String mfaVerified) {

    // Step 1: validate credentials (required — not the vulnerability here)
    if (!VALID_USER.equals(username) || !VALID_PASS.equals(password)) {
      return failed(this).feedback("mfa-client-trust.bad-creds").build();
    }

    // VULNERABILITY: The server trusts the client-supplied 'mfaVerified' parameter to determine
    // whether MFA was completed. An attacker with valid credentials simply sets mfaVerified=true
    // to bypass the second factor entirely. The OTP is never actually verified server-side.
    //
    // Correct implementation: the server must verify the OTP itself (call
    // OneTimeTokenService.consume()) and store the result in a server-side session attribute —
    // never in a client-supplied request parameter.
    if ("true".equalsIgnoreCase(mfaVerified.trim())) {
      return success(this).feedback("mfa-client-trust.success").build();
    }

    return failed(this)
        .feedback("mfa-client-trust.need-mfa")
        .output(
            "Credentials accepted but MFA is required. "
                + "The form has a hidden field that controls this check.")
        .build();
  }
}
