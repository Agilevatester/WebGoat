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

import java.security.SecureRandom;
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
 * MFA Recovery Flow Bypass — Technique 4 (DeepStrike).
 *
 * <p>Demonstrates a common architectural flaw: MFA is enforced on the normal login path but the
 * account-recovery (password-reset) path grants a fully-authenticated session without requiring
 * the second factor. An attacker who knows the target's email address can use the recovery flow
 * to bypass MFA entirely.
 *
 * <p><strong>Three operations:</strong>
 * <ul>
 *   <li>{@code POST /auth-bypass/mfa/recovery-login-step1} — validates credentials and generates
 *       a random OTP "sent to the device". The OTP is stored in session but never revealed here,
 *       making the normal two-factor flow impossible to complete without the physical device.
 *   <li>{@code POST /auth-bypass/mfa/recovery-login-step2} — verifies the OTP. Succeeds only
 *       with the correct (unknown) OTP. Students are NOT expected to complete this path.
 *   <li>{@code POST /auth-bypass/mfa/account-recovery} — VULNERABILITY: the recovery path
 *       requires only an email address and grants full access without any OTP. This is the
 *       assignment endpoint — students must discover and use this instead of the normal flow.
 * </ul>
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.mfa-recovery.1",
  "auth-bypass.hints.mfa-recovery.2",
  "auth-bypass.hints.mfa-recovery.3"
})
public class MfaRecoveryBypassEndpoint extends AssignmentEndpoint {

  static final String OTP_KEY = "mfa-recovery-otp";
  static final String VALID_USER = "admin";
  static final String VALID_PASS = "adminpass";
  static final String RECOVERY_EMAIL = "admin@webgoat.org";

  private static final SecureRandom RANDOM = new SecureRandom();

  @Autowired UserSessionData userSessionData;

  /**
   * Step 1 — submit credentials to initiate the normal MFA flow.
   *
   * <p>Generates a random OTP and stores it in the session (simulating out-of-band delivery to the
   * user's device). The OTP is intentionally NOT returned to the student, so the normal step-2
   * path cannot be completed without the physical device.
   */
  @PostMapping(
      path = "/auth-bypass/mfa/recovery-login-step1",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult step1(@RequestParam String username, @RequestParam String password) {

    if (!VALID_USER.equals(username) || !VALID_PASS.equals(password)) {
      return failed(this).feedback("mfa-recovery.bad-creds").build();
    }

    // Generate a random 6-digit OTP — not revealed to the student
    String otp = String.format("%06d", RANDOM.nextInt(1_000_000));
    userSessionData.setValue(OTP_KEY, otp);

    return failed(this)
        .feedback("mfa-recovery.step1-done")
        .output(
            "Credentials accepted. A 6-digit OTP has been sent to the registered device."
                + " Enter it below to complete sign-in."
                + " (If you cannot access your device, try the account recovery option.)")
        .build();
  }

  /**
   * Step 2 — submit the OTP to complete the normal MFA flow.
   *
   * <p>This path is intentionally uncompletable without the physical device (the OTP is a fresh
   * random value every time step 1 is triggered). Students are guided toward the recovery path.
   */
  @PostMapping(
      path = "/auth-bypass/mfa/recovery-login-step2",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult step2(@RequestParam String otp) {

    String stored = (String) userSessionData.getValue(OTP_KEY);
    if (stored == null) {
      return failed(this).feedback("mfa-recovery.step1-required").build();
    }

    if (stored.equals(otp != null ? otp.trim() : "")) {
      // Correct path — but students won't reach here without the device
      return success(this).feedback("mfa-recovery.normal-success").build();
    }

    return failed(this)
        .feedback("mfa-recovery.wrong-otp")
        .output("Incorrect OTP. Cannot access your device? Use account recovery instead.")
        .build();
  }

  /**
   * Account recovery endpoint — the assignment endpoint.
   *
   * <p>VULNERABILITY: The recovery flow requires only the registered email address and grants a
   * fully-authenticated session, bypassing MFA entirely. A secure implementation would require a
   * step-up authentication (re-verify identity via an additional channel) before the recovery
   * session is granted elevated access.
   */
  @PostMapping(
      path = "/auth-bypass/mfa/account-recovery",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult recovery(@RequestParam String email) {

    if (RECOVERY_EMAIL.equalsIgnoreCase(email != null ? email.trim() : "")) {
      return success(this).feedback("mfa-recovery.bypass-success").build();
    }

    return failed(this)
        .feedback("mfa-recovery.wrong-email")
        .output("No account found for '" + email + "'. Try the registered account email.")
        .build();
  }
}
