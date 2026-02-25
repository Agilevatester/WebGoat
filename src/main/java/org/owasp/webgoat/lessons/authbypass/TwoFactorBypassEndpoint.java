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

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.ThreadLocalRandom;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 2FA bypass lesson endpoint.
 *
 * <p>Teaches parameter omission bypass: the server only validates the OTP code when the
 * {@code code} parameter is present. Removing it from the request entirely bypasses the check —
 * the same class of flaw demonstrated in the PayPal 2FA bypass (2016).
 *
 * <p>Vulnerable logic mirrors {@link AccountVerificationHelper#verifyAccount}: if the parameter is
 * absent the conditional is never entered and the method returns success.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.2fa.1",
  "auth-bypass.hints.2fa.2",
  "auth-bypass.hints.2fa.3"
})
public class TwoFactorBypassEndpoint extends AssignmentEndpoint {

  // Simulated OTP that the application "sent" to the user's registered device.
  // Not secret in a real app — stored server-side and compared to submission.
  // Randomized at JVM startup so it is not a fixed hardcoded value.
  private static final String LESSON_OTP =
      String.format("%04d", ThreadLocalRandom.current().nextInt(0, 10_000));

  @PostMapping(
      path = "/auth-bypass/2fa-verify",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(@RequestParam String userId, HttpServletRequest req) {

    String submittedCode = req.getParameter("code");

    // Cheat detection: student found the hardcoded OTP and submitted it directly.
    // The learning goal is to bypass, not to guess.
    if (LESSON_OTP.equals(submittedCode)) {
      return failed(this)
          .feedback("auth-bypass.2fa.cheated")
          .output("You supplied the correct OTP, but the goal is to bypass verification without it.")
          .build();
    }

    // VULNERABILITY: the check is guarded by a null test — it only rejects a wrong code
    // when the parameter is actually present. If the attacker removes the 'code' parameter
    // from the request the block is skipped entirely and verification succeeds.
    if (submittedCode != null && !submittedCode.equals(LESSON_OTP)) {
      return failed(this).feedback("auth-bypass.2fa.failed").build();
    }

    // Reaching here means 'code' was absent from the request: bypass successful.
    return success(this).feedback("auth-bypass.2fa.success").build();
  }
}
