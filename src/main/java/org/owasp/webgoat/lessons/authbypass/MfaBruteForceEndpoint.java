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
 * Verification code submission endpoint for the portal login flow.
 *
 * <p>Accepts a time-sensitive verification code issued to the registered contact
 * method. The code must be submitted within the validity window to complete
 * authentication.
 *
 * <p>A supplementary status endpoint provides feedback on verification attempt
 * state without consuming a submission slot.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.mfa-bruteforce.1",
  "auth-bypass.hints.mfa-bruteforce.2",
  "auth-bypass.hints.mfa-bruteforce.3"
})
public class MfaBruteForceEndpoint extends AssignmentEndpoint {

  private static final String LESSON_OTP = "7528";

  /**
   * Verification code submission endpoint.
   *
   * <p>Validates the supplied code against the active verification token for
   * the current session. Returns success when the submitted value matches
   * the issued code.
   *
   * @param verificationCode  the code received on the registered contact method
   * @param sessionRef        session reference token forwarded by the client (audit only)
   */
  @PostMapping(
      path = "/auth-bypass/mfa/bruteforce-otp",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult verify(
      @RequestParam String verificationCode,
      @RequestParam(required = false, defaultValue = "") String sessionRef) {

    if (LESSON_OTP.equals(verificationCode != null ? verificationCode.trim() : "")) {
      return success(this).feedback("mfa-bruteforce.success").build();
    }

    return failed(this)
        .feedback("mfa-bruteforce.wrong")
        .output("Submitted code '" + verificationCode + "' is incorrect.")
        .build();
  }

  /**
   * Verification attempt status endpoint (decoy).
   *
   * <p>Returns the current verification state for the session without
   * consuming an attempt or validating any code.
   *
   * @param sessionRef  session reference token
   * @param channel     delivery channel used for the code (sms, email, app)
   */
  @PostMapping(
      path = "/auth-bypass/mfa/verification-status",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult verificationStatus(
      @RequestParam(required = false, defaultValue = "") String sessionRef,
      @RequestParam(required = false, defaultValue = "app") String channel) {

    return failed(this)
        .output("Verification pending via channel: " + channel + ".")
        .build();
  }
}
