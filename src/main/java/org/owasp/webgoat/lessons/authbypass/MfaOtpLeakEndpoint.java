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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * MFA OTP Leakage in HTTP Response Exercise.
 *
 * <p>Demonstrates DeepStrike Technique 2: a developer mistake causes the OTP to be included in
 * the server's HTTP response body (disguised as debug output), making it trivially readable by
 * anyone inspecting network traffic via browser DevTools or an intercepting proxy.
 *
 * <p>In a Spring Security 7 implementation using {@code OneTimeTokenService}, the generated token
 * is passed only to the {@code OneTimeTokenGenerationSuccessHandler}, which is responsible for
 * delivering it out-of-band (email, SMS). The token must never appear in the HTTP response
 * visible to the browser.
 *
 * <p><strong>Two operations:</strong>
 * <ul>
 *   <li>{@code POST /auth-bypass/mfa/send-otp} — VULNERABILITY: generates OTP and includes it
 *       in the {@code output} field of the response as a "debug comment". Stores OTP in session.
 *   <li>{@code POST /auth-bypass/mfa/verify-leaked-otp} — assignment endpoint. Succeeds when the
 *       student supplies the OTP they read from the previous response.
 * </ul>
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.mfa-otp-leak.1",
  "auth-bypass.hints.mfa-otp-leak.2",
  "auth-bypass.hints.mfa-otp-leak.3"
})
public class MfaOtpLeakEndpoint extends AssignmentEndpoint {

  static final String OTP_SESSION_KEY = "mfa-leaked-otp";
  // Fixed OTP for predictability in the lesson context.
  // In a real app this would be a securely-random short-lived value.
  static final String LESSON_OTP =  String.format("%04d", ThreadLocalRandom.current().nextInt(0, 10_000));

  @Autowired UserSessionData userSessionData;

  /**
   * Sends (simulates) an OTP to the user's registered device.
   *
   * <p>VULNERABILITY: the generated OTP is embedded in the {@code output} response field,
   * disguised as an HTML comment. A developer added this for debugging and forgot to remove it.
   * Anyone inspecting the HTTP response in browser DevTools can read the value.
   */
  @PostMapping(
      path = "/auth-bypass/mfa/send-otp",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult sendOtp(@RequestParam String username) {

    userSessionData.setValue(OTP_SESSION_KEY, LESSON_OTP);

    // VULNERABILITY: OTP written to the response body.
    // The correct implementation (Spring Security 7 OneTimeTokenGenerationSuccessHandler)
    // delivers the token exclusively via the out-of-band channel and NEVER includes it here.
    return failed(this)
        .feedback("mfa-otp-leak.sent")
        .output(
            "A one-time code has been dispatched to the registered email address."
                + " <!-- DEBUG otp_value="
                + LESSON_OTP
                + " remove before production -->")
        .build();
  }

  /**
   * Verifies the OTP submitted by the user — the assignment endpoint.
   *
   * <p>Succeeds when the student reads the leaked OTP from the {@code /send-otp} response and
   * submits it here, demonstrating that response-body leakage renders MFA trivially bypassable.
   */
  @PostMapping(
      path = "/auth-bypass/mfa/verify-leaked-otp",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult verifyOtp(@RequestParam String otp) {

    String stored = (String) userSessionData.getValue(OTP_SESSION_KEY);

    if (stored == null) {
      return failed(this).feedback("mfa-otp-leak.not-generated").build();
    }

    if (stored.equals(otp != null ? otp.trim() : "")) {
      return success(this).feedback("mfa-otp-leak.success").build();
    }

    return failed(this).feedback("mfa-otp-leak.wrong").build();
  }
}
