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
 * MFA OTP Brute Force — Technique 3 (DeepStrike).
 *
 * <p>Demonstrates the absence of rate-limiting or lockout on a One-Time Password verification
 * endpoint. Short numeric OTPs (6 digits = 10^6 values) are trivially brute-forceable when the
 * server imposes no attempt counter, no lockout threshold, and no CAPTCHA.
 *
 * <p>This endpoint intentionally accepts unlimited submissions against the same OTP. A correct
 * implementation would track failed attempts per session and lock the OTP (or the session) after
 * a small number of failures — for example, the approach used by Spring Security 7's
 * {@code InMemoryOneTimeTokenService} which invalidates a token after a single successful
 * consumption, but leaves rate-limiting to the application layer.
 *
 * <p>The OTP for this exercise is a fixed 4-digit value. Students are expected to discover it
 * using an intercepting proxy (Burp Suite Intruder, OWASP ZAP Fuzzer) or curl loop, then submit
 * it here. Hint 3 reveals the value for students who want to focus on the concept rather than the
 * automation.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.mfa-bruteforce.1",
  "auth-bypass.hints.mfa-bruteforce.2",
  "auth-bypass.hints.mfa-bruteforce.3"
})
public class MfaBruteForceEndpoint extends AssignmentEndpoint {

  // Fixed OTP for the lesson. In a real app this would be a per-session random value.
  // The correct fix: expire the OTP after N failed attempts (3–5 is standard).
  private static final String LESSON_OTP = "7528";

  @PostMapping(
      path = "/auth-bypass/mfa/bruteforce-otp",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult verify(@RequestParam String otp) {

    // VULNERABILITY: Every request is treated independently with no attempt tracking.
    // An automated tool submitting 0000–9999 will find this in under a second.
    if (LESSON_OTP.equals(otp != null ? otp.trim() : "")) {
      return success(this).feedback("mfa-bruteforce.success").build();
    }

    return failed(this)
        .feedback("mfa-bruteforce.wrong")
        .output("Submitted OTP '" + otp + "' is incorrect. No lockout — try again.")
        .build();
  }
}
