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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Brute-Force Rate-Limit Bypass via X-Forwarded-For header spoofing.
 * Inspired by EDB-49037 (Bludit CMS 3.9.2).
 *
 * <p>Bludit's login endpoint tracked failed attempts per client IP to block brute-force attacks.
 * Because the application resolved the client IP from the {@code X-Forwarded-For} header — which
 * is fully attacker-controlled — an attacker could supply a new spoofed IP on every request,
 * resetting the counter and allowing unlimited password guessing.
 *
 * <p>This exercise reproduces the flaw. After {@value MAX_ATTEMPTS} failed attempts the "IP" is
 * locked. Students must bypass the lockout by adding or rotating the {@code X-Forwarded-For}
 * header, then authenticate with the correct credentials ({@code admin} / {@code tomcat}).
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.ratelimit.1",
  "auth-bypass.hints.ratelimit.2",
  "auth-bypass.hints.ratelimit.3"
})
public class RateLimitBypassEndpoint extends AssignmentEndpoint {

  // In a production app this store would live in Redis/Memcached.
  // Per-JVM in-memory storage is sufficient for a single-node lesson.
  private static final ConcurrentHashMap<String, AtomicInteger> failedAttempts =
      new ConcurrentHashMap<>();

  private static final int MAX_ATTEMPTS = 3;

  // Credentials published in the exercise documentation — the goal is the bypass, not guessing.
  private static final String VALID_USERNAME = "admin";
  private static final String VALID_PASSWORD = "tomcat";

  @PostMapping(
      path = "/auth-bypass/brute-login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult login(
      @RequestParam String username,
      @RequestParam String password,
      HttpServletRequest request) {

    String clientIp = resolveClientIp(request);

    AtomicInteger attempts = failedAttempts.computeIfAbsent(clientIp, k -> new AtomicInteger(0));

    if (attempts.get() >= MAX_ATTEMPTS) {
      return failed(this)
          .feedback("auth-bypass.ratelimit.locked")
          .output(
              "IP address '"
                  + clientIp
                  + "' is locked after "
                  + MAX_ATTEMPTS
                  + " failed attempts. Change your apparent IP to continue.")
          .build();
    }

    if (VALID_USERNAME.equals(username) && VALID_PASSWORD.equals(password)) {
      failedAttempts.remove(clientIp);
      return success(this).feedback("auth-bypass.ratelimit.success").build();
    }

    int count = attempts.incrementAndGet();
    return failed(this)
        .feedback("auth-bypass.ratelimit.failed")
        .output("Failed attempt " + count + "/" + MAX_ATTEMPTS + " from IP: " + clientIp)
        .build();
  }

  /**
   * VULNERABILITY: Resolves the client IP from the {@code X-Forwarded-For} header without
   * validation. A trusted proxy should be the only source allowed to set this header. Accepting it
   * from arbitrary clients lets attackers inject any IP they choose.
   *
   * <p>The safe fix: only honour {@code X-Forwarded-For} when the request originates from a known,
   * trusted reverse-proxy address; ignore it from all other sources.
   */
  private String resolveClientIp(HttpServletRequest request) {
    String xff = request.getHeader("X-Forwarded-For");
    if (xff != null && !xff.isBlank()) {
      // Take the first (leftmost) address — the claimed original client IP.
      return xff.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }
}
