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
 * MFA authentication endpoint for the portal login flow.
 *
 * <p>Accepts credentials and a session state value forwarded by the client-side authentication
 * library. The login sequence requires valid credentials before the second-factor check is
 * evaluated.
 *
 * <p>A secondary resend endpoint allows users to request a new verification code without
 * re-entering credentials.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.mfa-client-trust.1",
  "auth-bypass.hints.mfa-client-trust.2",
  "auth-bypass.hints.mfa-client-trust.3"
})
public class MfaClientTrustEndpoint extends AssignmentEndpoint {

  private static final String VALID_USER = "admin";
  private static final String VALID_PASS = "password123";

  /**
   * Primary login endpoint.
   *
   * <p>Validates credentials and evaluates the authentication state forwarded by the client
   * library. Both the credential check and the session state must succeed for access to be granted.
   *
   * @param username        account username
   * @param password        account password
   * @param sessionVerified authentication state forwarded from the client library
   * @param deviceId        registered device identifier (audit only)
   * @param appVersion      client application version (audit only)
   */
  @PostMapping(
      path = "/auth-bypass/mfa/client-trust-login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult login(
      @RequestParam String username,
      @RequestParam String password,
      @RequestParam(defaultValue = "false") String sessionVerified,
      @RequestParam(required = false, defaultValue = "") String deviceId,
      @RequestParam(required = false, defaultValue = "") String appVersion) {

    if (!VALID_USER.equals(username) || !VALID_PASS.equals(password)) {
      return failed(this).feedback("mfa-client-trust.bad-creds").build();
    }

    if ("true".equalsIgnoreCase(sessionVerified.trim())) {
      return success(this).feedback("mfa-client-trust.success").build();
    }

    return failed(this)
        .feedback("mfa-client-trust.need-mfa")
        .output("Credentials accepted. Complete MFA verification to continue.")
        .build();
  }

  /**
   * Resend verification code endpoint (decoy).
   *
   * <p>Accepts a username and device identifier and queues a new MFA code dispatch. No state
   * modification affecting the login flow occurs on this path.
   *
   * @param username  account username
   * @param deviceId  registered device identifier
   */
  @PostMapping(
      path = "/auth-bypass/mfa/resend-code",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult resendCode(
      @RequestParam(required = false, defaultValue = "") String username,
      @RequestParam(required = false, defaultValue = "") String deviceId) {

    return failed(this)
        .output("Verification code dispatched to registered device"
            + (deviceId.isEmpty() ? "." : " (" + deviceId + ")."))
        .build();
  }
}
