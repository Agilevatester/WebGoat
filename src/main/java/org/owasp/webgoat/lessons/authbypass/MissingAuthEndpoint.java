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
 * Missing Authentication Check — inspired by CVE-2024-4358 (Progress Telerik Report Server).
 *
 * <p>In the real vulnerability, the {@code /Startup/Register} endpoint was accessible without any
 * authentication, allowing an attacker to self-register an account with arbitrary roles and
 * receive a valid JWT token. That token was then used to upload a malicious report payload leading
 * to Remote Code Execution.
 *
 * <p>This exercise simulates the core flaw: a registration endpoint accepts a {@code role}
 * parameter and assigns it directly without verifying that the caller is authorised to grant
 * elevated roles. The fix is to enforce server-side authorisation — never trust role values
 * supplied by the client.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.missing-auth.1",
  "auth-bypass.hints.missing-auth.2",
  "auth-bypass.hints.missing-auth.3"
})
public class MissingAuthEndpoint extends AssignmentEndpoint {

  @PostMapping(
      path = "/auth-bypass/missing-auth-register",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult register(
      @RequestParam String username,
      @RequestParam String email,
      @RequestParam String role) {

    // VULNERABILITY: No authentication or authorisation check.
    // Any caller — authenticated or not — can POST to this endpoint and supply
    // role=admin to grant themselves administrator privileges.
    // A correct implementation would:
    //   1. Verify the caller holds an existing admin session.
    //   2. Ignore or reject any client-supplied role that exceeds their current privilege.
    if ("admin".equalsIgnoreCase(role.trim())) {
      return success(this).feedback("auth-bypass.missing-auth.success").build();
    }

    return failed(this).feedback("auth-bypass.missing-auth.not-admin").build();
  }
}
