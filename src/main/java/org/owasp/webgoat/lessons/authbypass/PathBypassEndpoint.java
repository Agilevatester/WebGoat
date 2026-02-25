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
 * Path Traversal Authentication Bypass — inspired by CVE-2024-27198 (JetBrains TeamCity).
 *
 * <p>In the real vulnerability the TeamCity authentication filter checked {@code
 * request.getRequestURI()} using string pattern matching. An attacker crafted URLs such as
 * {@code /idontexist?jsp=/app/rest/users;.jsp}: the filter saw {@code /idontexist} (an
 * unprotected path) while the JSP handler resolved and executed {@code /app/rest/users},
 * granting unauthenticated admin access.
 *
 * <p>This exercise simulates the root cause at the parameter level: a "WAF" checks the raw
 * {@code requestedPath} value using exact string comparison against {@code /admin}. The server
 * then resolves the path through normalisation (stripping semicolons, decoding percent-encoding,
 * collapsing double slashes) — the same steps a real framework router would perform. A path that
 * looks harmless to the WAF can resolve to {@code /admin} after normalisation.
 *
 * <p>Valid bypass inputs include:
 * <ul>
 *   <li>{@code /admin;.css} — semicolon path parameter stripped by the server</li>
 *   <li>{@code //admin} — double slash collapsed to single slash</li>
 *   <li>{@code /%61dmin} — percent-encoded {@code a} decoded to produce {@code /admin}</li>
 * </ul>
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.path.1",
  "auth-bypass.hints.path.2",
  "auth-bypass.hints.path.3"
})
public class PathBypassEndpoint extends AssignmentEndpoint {

  @PostMapping(
      path = "/auth-bypass/path-bypass",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult bypass(@RequestParam String requestedPath) {

    if (requestedPath == null || requestedPath.isBlank()) {
      return failed(this).feedback("auth-bypass.path.empty").build();
    }

    // VULNERABILITY: The simulated WAF/auth filter performs a raw exact-match check
    // on the user-supplied path string before any normalisation occurs. This mirrors
    // a pattern-matching security filter that runs before the URL is decoded/resolved.
    if ("/admin".equals(requestedPath)) {
      return failed(this)
          .feedback("auth-bypass.path.blocked")
          .output("The security filter blocked the direct request to /admin.")
          .build();
    }

    // The server normalises the path AFTER the security filter has already passed —
    // exactly as happened in CVE-2024-27198 where routing happened post-filter.
    String resolvedPath = normalizePath(requestedPath);

    if ("/admin".equals(resolvedPath)) {
      // The raw value bypassed the WAF; the resolved value is still /admin.
      return success(this)
          .feedback("auth-bypass.path.success")
          .output(
              "Raw input: '"
                  + requestedPath
                  + "' → resolved: '"
                  + resolvedPath
                  + "'. The filter never saw /admin, but the server executed it.")
          .build();
    }

    return failed(this)
        .feedback("auth-bypass.path.not-admin")
        .output("Resolved path: '" + resolvedPath + "' — does not map to the admin resource.")
        .build();
  }

  /**
   * Simulates server-side path normalisation that runs AFTER the security filter.
   *
   * <ul>
   *   <li>Step 1 — strip semicolon path parameters: {@code /admin;.css} → {@code /admin}</li>
   *   <li>Step 2 — decode common percent-encoded characters: {@code %61} / {@code %41} → {@code a}
   *   </li>
   *   <li>Step 3 — collapse consecutive slashes: {@code //admin} → {@code /admin}</li>
   * </ul>
   */
  private String normalizePath(String raw) {
    // Strip semicolon path-parameters (RFC 2396 §3.3)
    String result = raw.contains(";") ? raw.substring(0, raw.indexOf(';')) : raw;
    // Decode percent-encoded 'a' / 'A' (simplified for lesson clarity)
    result = result.replace("%61", "a").replace("%41", "A");
    // Collapse repeated slashes
    result = result.replaceAll("/+", "/");
    return result;
  }
}
