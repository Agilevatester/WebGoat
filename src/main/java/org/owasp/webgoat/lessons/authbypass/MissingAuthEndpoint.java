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
 * Account provisioning service.
 *
 * <p>Provides a self-registration endpoint for new accounts and a separate profile-update endpoint
 * for existing users. The registration endpoint accepts account details including an account tier
 * that is applied to the new account during provisioning.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.missing-auth.1",
  "auth-bypass.hints.missing-auth.2",
  "auth-bypass.hints.missing-auth.3"
})
public class MissingAuthEndpoint extends AssignmentEndpoint {

  /**
   * Self-registration endpoint.
   *
   * <p>Accepts account details and provisions a new account. The {@code accountTier} parameter
   * specifies the access level to grant. Provisioning completes without verifying the caller's
   * authorisation to request elevated tiers.
   *
   * @param username     desired account username
   * @param email        account email address
   * @param accountTier  access tier for the new account (user, manager, admin, etc.)
   * @param orgId        organisation identifier for multi-tenant provisioning (display only)
   * @param referralCode optional referral code applied at registration (display only)
   */
  @PostMapping(
      path = "/auth-bypass/missing-auth-register",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult register(
      @RequestParam String username,
      @RequestParam String email,
      @RequestParam String accountTier,
      @RequestParam(required = false, defaultValue = "") String orgId,
      @RequestParam(required = false, defaultValue = "") String referralCode) {

    if ("admin".equalsIgnoreCase(accountTier.trim())) {
      return success(this).feedback("auth-bypass.missing-auth.success").build();
    }

    return failed(this).feedback("auth-bypass.missing-auth.not-admin").build();
  }

  /**
   * Profile update endpoint (decoy).
   *
   * <p>Accepts updated display name and notification preferences for an existing account.
   * No tier elevation or privileged field modification occurs on this path.
   *
   * @param username      account username
   * @param displayName   updated display name
   * @param notifications notification preference (all, mentions, none)
   */
  @PostMapping(
      path = "/auth-bypass/missing-auth-profile",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult updateProfile(
      @RequestParam(required = false, defaultValue = "") String username,
      @RequestParam(required = false, defaultValue = "") String displayName,
      @RequestParam(required = false, defaultValue = "all") String notifications) {

    return failed(this)
        .output("Profile updated for account: " + username
            + " | notifications=" + notifications)
        .build();
  }
}
