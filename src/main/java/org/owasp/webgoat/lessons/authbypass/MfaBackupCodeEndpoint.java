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

import java.util.Set;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Account recovery code service.
 *
 * <p>Provides two endpoints for the emergency recovery flow. The recovery
 * code retrieval endpoint returns the account's registered recovery codes
 * for the authenticated session. The recovery login endpoint accepts a
 * recovery code in place of the primary second factor.
 *
 * <p>A supplementary regeneration endpoint allows users to request a new
 * set of recovery codes when the existing set is depleted.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.mfa-backup.1",
  "auth-bypass.hints.mfa-backup.2",
  "auth-bypass.hints.mfa-backup.3"
})
public class MfaBackupCodeEndpoint extends AssignmentEndpoint {

  private static final Set<String> RECOVERY_CODES =
      Set.of("WGAT-7291", "WGAT-4823", "WGAT-9035", "WGAT-6147", "WGAT-3582");

  /**
   * Recovery code retrieval endpoint.
   *
   * <p>Returns the recovery codes registered to the current account.
   * Codes are returned in their active form for use in the recovery login flow.
   *
   * @param accountRef  account reference for the retrieval request (audit only)
   * @param format      output format for the code list (plain, masked)
   */
  @PostMapping(
      path = "/auth-bypass/mfa/reveal-backup-codes",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult revealCodes(
      @RequestParam(required = false, defaultValue = "") String accountRef,
      @RequestParam(required = false, defaultValue = "plain") String format) {

    String codes = String.join(" | ", RECOVERY_CODES);
    return failed(this)
        .feedback("mfa-backup.codes-revealed")
        .output(
            "Recovery codes for this account:\n"
                + codes
                + "\n\nStore these in a secure location. "
                + "Each code may be used once in place of your primary authenticator.")
        .build();
  }

  /**
   * Recovery code login endpoint — assignment check.
   *
   * <p>Accepts a recovery code and grants access when it matches an active
   * code in the account's recovery set.
   *
   * @param recoveryCode  the recovery code to authenticate with
   * @param accountRef    account reference forwarded by the client (audit only)
   */
  @PostMapping(
      path = "/auth-bypass/mfa/backup-code-login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult loginWithBackup(
      @RequestParam String recoveryCode,
      @RequestParam(required = false, defaultValue = "") String accountRef) {

    String normalised = recoveryCode != null ? recoveryCode.trim().toUpperCase() : "";

    if (RECOVERY_CODES.contains(normalised)) {
      return success(this).feedback("mfa-backup.success").build();
    }

    return failed(this)
        .feedback("mfa-backup.wrong")
        .output("Code '" + recoveryCode + "' is not recognised. Retrieve your recovery codes first.")
        .build();
  }

  /**
   * Recovery code regeneration endpoint (decoy).
   *
   * <p>Accepts a request to regenerate the recovery code set. Returns a
   * confirmation message. No codes are modified on this path.
   *
   * @param accountRef  account reference for the regeneration request
   * @param reason      reason for regeneration (depleted, compromised, routine)
   */
  @PostMapping(
      path = "/auth-bypass/mfa/regenerate-codes",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult regenerateCodes(
      @RequestParam(required = false, defaultValue = "") String accountRef,
      @RequestParam(required = false, defaultValue = "routine") String reason) {

    return failed(this)
        .output("Recovery code regeneration queued for account"
            + (accountRef.isEmpty() ? "." : " (" + accountRef + ")."))
        .build();
  }
}
