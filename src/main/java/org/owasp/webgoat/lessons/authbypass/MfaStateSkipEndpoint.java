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

import java.util.concurrent.ThreadLocalRandom;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.UserSessionData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * MFA State-Skip (Force Browse) Bypass Exercise.
 *
 * <p>
 * Demonstrates DeepStrike Technique 1: after the first factor (password) is
 * verified the server
 * issues a half-authenticated session. A secure implementation — such as the
 * one described in the
 * Spring Security 7 MFA API — attaches a {@code FactorGrantedAuthority} to the
 * session for each
 * completed factor and blocks access to any protected resource until all
 * required factors are
 * present.
 *
 * <p>
 * This endpoint is <em>vulnerable</em> because the protected-resource handler
 * only checks that
 * the password factor was completed; it never verifies that the OTP (second)
 * factor was also done.
 * A student who completes step 1 and then directly accesses the protected
 * resource — skipping the
 * OTP form — will succeed.
 *
 * <p>
 * <strong>Two operations in one {@code @RestController}:</strong>
 * <ul>
 * <li>{@code POST /auth-bypass/mfa/credentials} — verifies password, stores the
 * step-1 flag
 * in {@link UserSessionData}. Returns a {@code failed} {@link AttackResult}
 * (not a lesson
 * completion — just interim feedback) so the WebGoat AJAX form gets a parseable
 * response.
 * <li>{@code POST /auth-bypass/mfa/access} — the actual assignment endpoint.
 * Returns
 * {@code success} when step 1 is done but step 2 is absent (the bypass), and
 * {@code failed}
 * otherwise.
 * </ul>
 */
@RestController
@AssignmentHints({
    "auth-bypass.hints.mfa-state-skip.1",
    "auth-bypass.hints.mfa-state-skip.2",
    "auth-bypass.hints.mfa-state-skip.3"
})
public class MfaStateSkipEndpoint extends AssignmentEndpoint {

  static final String STEP1_KEY = "mfa-skip-step1-done";
  static final String STEP2_KEY = "mfa-skip-step2-done";
  static final String VALID_USER = "admin";
  static final String VALID_PASS = "admin123";
  static final String OTP_KEY = "mfa-skip-otp";
  
  @Autowired
  UserSessionData userSessionData;

  /**
   * Step 1 — validate the first factor (password).
   *
   * <p>
   * On success the step-1 flag is written to the user session. Returns a
   * {@code failed}
   * AttackResult (interim feedback) so the WebGoat framework can render the
   * response without
   * marking the lesson as complete.
   */
  @PostMapping(path = "/auth-bypass/mfa/credentials", consumes = { "application/json" }, produces = {
      "application/json" })
  @ResponseBody
  public AttackResult credentials(@RequestBody JsonNode body) {
    String username = body != null && body.has("username") ? body.get("username").asText("") : "";
    String password = body != null && body.has("password") ? body.get("password").asText("") : "";

    if (VALID_USER.equals(username) && VALID_PASS.equals(password)) {
      userSessionData.setValue(STEP1_KEY, "true");
      // New login attempt resets OTP completion state
      userSessionData.setValue(STEP2_KEY, "false");
      String otp = String.format("%06d", ThreadLocalRandom.current().nextInt(0, 1_000_000));
      userSessionData.setValue(OTP_KEY, otp);
      return failed(this)
          .feedback("mfa-state-skip.step1-done")
          .output(
              "MFA_STATE_SKIP:STEP1_OK "
                  + "Password accepted. A one-time code has been dispatched to the registered device."
                  + " You should enter it below before accessing any protected resource."
                  + "Enter the OTP in Step 2, then access the protected resource in Step 3.")
          .build();
    }
    userSessionData.setValue(STEP1_KEY, "false");
    userSessionData.setValue(STEP2_KEY, "false");

    return failed(this).feedback("mfa-state-skip.bad-credentials").build();
  }

  /**
   * Step 2 — verify the OTP (simulated normal MFA flow).
   *
   * <p>
   * This is intentionally not the assignment-completion endpoint. It returns an
   * interim
   * response so the learner can continue to Step 3. The vulnerability remains in
   * /mfa/access.
   */
  @PostMapping(path = "/auth-bypass/mfa/otp-verify", consumes = { "application/json" }, produces = {
      "application/json" })
  @ResponseBody
  public AttackResult verifyOtp(@RequestBody JsonNode body) {
    String step1 = (String) userSessionData.getValue(STEP1_KEY);
    if (!"true".equals(step1)) {
      return failed(this).feedback("mfa-state-skip.step1-required").build();
    }

    String otp = body != null && body.has("otp") ? body.get("otp").asText("") : "";
    Object expectedOtp = userSessionData.getValue(OTP_KEY);
    if (expectedOtp == null || !expectedOtp.equals(otp)) {
      return failed(this).feedback("mfa-state-skip.otp-invalid").build();
    }

    userSessionData.setValue(STEP2_KEY, "true");
    return failed(this)
        .feedback("mfa-state-skip.otp-accepted")
        .output("MFA_STATE_SKIP:OTP_OK OTP accepted. Step 3 is now available.")
        .build();
  }

  /**
   * Protected resource — the assignment endpoint.
   *
   * <p>
   * VULNERABILITY: only checks that the password factor was completed
   * ({@code step1}). It never
   * verifies the OTP factor ({@code step2}). A correct Spring Security 7
   * implementation would
   * require {@code FactorGrantedAuthority.PASSWORD_AUTHORITY} AND
   * {@code FactorGrantedAuthority.OTT_AUTHORITY} before granting access.
   */
  @PostMapping(path = "/auth-bypass/mfa/access", consumes = { "application/json" }, produces = { "application/json" })
  @ResponseBody
  public AttackResult access(@RequestBody(required = false) JsonNode body) {
    String step1 = (String) userSessionData.getValue(STEP1_KEY);
    String step2 = (String) userSessionData.getValue(STEP2_KEY);

    if (!"true".equals(step1)) {
      return failed(this).feedback("mfa-state-skip.step1-required").build();
    }

    // VULNERABILITY: the OTP step is never checked.
    // Replace this entire block with a check for a second session flag (step2)
    // to make this endpoint secure.

    return success(this)
        .feedback("mfa-state-skip.success")
        .output(
            "DEBUG session factors: password="
                + step1
                + ", otp="
                + step2
                + " (access granted because OTP factor is not enforced)")
        .build();
  }
}
