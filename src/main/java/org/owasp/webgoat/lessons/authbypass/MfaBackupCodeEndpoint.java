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
 * MFA Backup Code Abuse — Technique 5 (DeepStrike).
 *
 * <p>Backup codes are single-use emergency credentials intended for situations where the primary
 * second factor is unavailable. Their security depends on two properties:
 * <ol>
 *   <li>They are stored hashed (not plaintext) and never shown again after initial generation.
 *   <li>Viewing or regenerating them requires step-up authentication (re-verifying identity
 *       including the second factor before revealing the codes).
 * </ol>
 *
 * <p>This endpoint is vulnerable on both counts:
 * <ul>
 *   <li>{@code POST /auth-bypass/mfa/reveal-backup-codes} — returns backup codes in plaintext
 *       with no step-up authentication. Any half-authenticated (password-only) or even
 *       unauthenticated caller can retrieve them.
 *   <li>{@code POST /auth-bypass/mfa/backup-code-login} — accepts a backup code and grants full
 *       access. This is the assignment endpoint.
 * </ul>
 *
 * <p>The exercise flow: call the reveal endpoint → read the backup codes from the output → submit
 * one of them to the login endpoint.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.mfa-backup.1",
  "auth-bypass.hints.mfa-backup.2",
  "auth-bypass.hints.mfa-backup.3"
})
public class MfaBackupCodeEndpoint extends AssignmentEndpoint {

  // Backup codes stored in plaintext — a real implementation hashes these with bcrypt.
  private static final Set<String> BACKUP_CODES =
      Set.of("WGAT-7291", "WGAT-4823", "WGAT-9035", "WGAT-6147", "WGAT-3582");

  /**
   * VULNERABILITY: Returns backup codes with no step-up authentication.
   *
   * <p>The endpoint should require the caller to prove they hold BOTH factors before displaying
   * emergency codes. Without that check, an attacker who has only the password can call this
   * endpoint directly and obtain permanent bypass credentials.
   */
  @PostMapping(
      path = "/auth-bypass/mfa/reveal-backup-codes",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult revealCodes() {

    // No auth check of any kind — the endpoint is wide open.
    String codes = String.join(" | ", BACKUP_CODES);
    return failed(this)
        .feedback("mfa-backup.codes-revealed")
        .output(
            "Your emergency backup codes (each valid for one use):\n"
                + codes
                + "\n\nStore these in a safe place. "
                + "They can be used instead of your authenticator app.")
        .build();
  }

  /**
   * Authenticates using a backup code — the assignment endpoint.
   *
   * <p>A correctly implemented backup-code endpoint would:
   * <ol>
   *   <li>Compare against a <em>hashed</em> store, not a plaintext set.
   *   <li>Atomically mark the code as consumed and remove it (truly single-use).
   *   <li>Notify the account owner via email that a backup code was used.
   * </ol>
   */
  @PostMapping(
      path = "/auth-bypass/mfa/backup-code-login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult loginWithBackup(@RequestParam String backupCode) {

    String normalised = backupCode != null ? backupCode.trim().toUpperCase() : "";

    if (BACKUP_CODES.contains(normalised)) {
      return success(this).feedback("mfa-backup.success").build();
    }

    return failed(this)
        .feedback("mfa-backup.wrong")
        .output("Code '" + backupCode + "' is not valid. Have you revealed your backup codes yet?")
        .build();
  }
}
