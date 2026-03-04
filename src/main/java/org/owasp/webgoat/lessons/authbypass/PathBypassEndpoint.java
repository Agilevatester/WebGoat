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
 * Resource access gateway service.
 *
 * <p>Routes resource access requests through a two-stage path evaluation pipeline. An ingress
 * filter inspects the raw request path before it is passed to the routing layer. The routing
 * layer normalises the path before resolving the target resource.
 *
 * <p>A diagnostics endpoint accepts the same path parameter for dry-run path normalisation
 * without accessing any protected resources.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.path.1",
  "auth-bypass.hints.path.2",
  "auth-bypass.hints.path.3"
})
public class PathBypassEndpoint extends AssignmentEndpoint {

  /**
   * Resource access endpoint.
   *
   * <p>Passes the requested path through the ingress filter before forwarding it to the routing
   * layer. The filter and the router operate on different representations of the same path value,
   * which may produce different evaluation outcomes for the same input.
   *
   * @param requestedPath  path of the resource to access
   */
  @PostMapping(
      path = "/auth-bypass/path-bypass",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult bypass(@RequestParam String requestedPath) {

    if (requestedPath == null || requestedPath.isBlank()) {
      return failed(this).feedback("auth-bypass.path.empty").build();
    }

    // Ingress filter: evaluates the raw path value
    if ("/admin".equals(requestedPath)) {
      return failed(this)
          .feedback("auth-bypass.path.blocked")
          .output("The ingress filter blocked access to this resource.")
          .build();
    }

    // Routing layer: normalises the path before resolving the target
    String resolvedPath = normalizePath(requestedPath);

    if ("/admin".equals(resolvedPath)) {
      return success(this)
          .feedback("auth-bypass.path.success")
          .output(
              "Submitted path: '"
                  + requestedPath
                  + "' → resolved: '"
                  + resolvedPath
                  + "'. The filter passed the request; the router resolved it to the protected resource.")
          .build();
    }

    return failed(this)
        .feedback("auth-bypass.path.not-admin")
        .output("Resolved path: '" + resolvedPath + "' — resource not found.")
        .build();
  }

  /**
   * Path normalisation diagnostics endpoint (decoy).
   *
   * <p>Accepts a path and returns its normalised form without performing any access control
   * evaluation. Intended for debugging the routing layer's normalisation behaviour.
   *
   * @param requestedPath  path to normalise
   * @param traceMode      whether to include step-by-step normalisation trace in the output
   */
  @PostMapping(
      path = "/auth-bypass/path-diagnostics",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult pathDiagnostics(
      @RequestParam(required = false, defaultValue = "/data") String requestedPath,
      @RequestParam(required = false, defaultValue = "false") String traceMode) {

    String resolved = normalizePath(requestedPath);
    return failed(this)
        .output("Input: '" + requestedPath + "' → Normalised: '" + resolved + "'")
        .build();
  }

  /**
   * Server-side path normalisation — runs after the ingress filter.
   *
   * <ul>
   *   <li>Strips semicolon path parameters (e.g. {@code /path;ext} → {@code /path})</li>
   *   <li>Decodes percent-encoded characters ({@code %61} / {@code %41} → {@code a})</li>
   *   <li>Collapses consecutive slashes ({@code //path} → {@code /path})</li>
   * </ul>
   */
  private String normalizePath(String raw) {
    String result = raw.contains(";") ? raw.substring(0, raw.indexOf(';')) : raw;
    result = result.replace("%61", "a").replace("%41", "A");
    result = result.replaceAll("/+", "/");
    return result;
  }
}
