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

package org.owasp.webgoat.lessons.ossspringspel;

import java.util.UUID;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring SpEL Injection — direct expression evaluation vulnerability.
 *
 * <p>This lesson demonstrates the class of vulnerability where a Spring application passes
 * untrusted user input directly to {@link SpelExpressionParser#parseExpression} and evaluates the
 * result. This is the same core flaw exploited in CVE-2022-22980 (Spring Data MongoDB) and
 * CVE-2023-20863 (Spring Framework).
 *
 * <h3>The Vulnerable Pattern</h3>
 *
 * <pre>{@code
 * ExpressionParser parser = new SpelExpressionParser();
 * Object result = parser.parseExpression(userInput).getValue();
 * }</pre>
 *
 * <p>Because {@code SpelExpressionParser} can call static methods via {@code T(ClassName).method}
 * syntax, an attacker can execute arbitrary Java code — including {@code Runtime.exec()} — when
 * user input reaches this call without sanitisation.
 *
 * <h3>Challenge</h3>
 *
 * <p>This lesson generates a one-time challenge token at startup. The token is accessible via a
 * static method on this class. To complete the lesson, use SpEL injection to exfiltrate the token
 * and submit it below. The token changes every time the server restarts, so automated guessing
 * is not possible.
 *
 * <p>The application accepts several form fields. Only one of them is evaluated as a SpEL
 * expression — identify it through experimentation, not through reading this source code.
 */
@RestController
@AssignmentHints({
  "spel-injection.hint.1",
  "spel-injection.hint.2",
  "spel-injection.hint.3",
  "spel-injection.hint.4"
})
public class SpringSpelInjectionEndpoint extends AssignmentEndpoint {

  private static final Logger log = LoggerFactory.getLogger(SpringSpelInjectionEndpoint.class);

  /**
   * One-time challenge token generated at JVM startup. Changes on every restart so it cannot be
   * guessed or hallucinated by automated tooling — the correct value must be obtained by actually
   * executing SpEL on the server.
   */
  private static final String   CHALLENGE_TOKEN =
      UUID.randomUUID().toString().replace("-", "").substring(0, 12).toUpperCase();

  private final ExpressionParser parser = new SpelExpressionParser();

  /**
   * Called by the SpEL injection payload to exfiltrate the challenge token.
   *
   * <p>Example payload: {@code T(org.owasp.webgoat.lessons.ossspringspel.SpringSpelInjectionEndpoint).getToken()}
   */
  public static String getToken() {
    return CHALLENGE_TOKEN;
  }

  /**
   * Employee performance-review search endpoint.
   *
   * <p>Accepts several parameters describing the search criteria. One parameter is consumed by an
   * internal reporting pipeline that uses {@link SpelExpressionParser} without sanitisation.
   * The others are handled safely.
   *
   * @param employeeId  employee identifier (safely handled)
   * @param reviewYear  review year — four digits (safely handled)
   * @param department  department code (safely handled)
   * @param outputView  output formatting identifier — <strong>VULNERABLE</strong>; passed directly
   *                    to {@code SpelExpressionParser.parseExpression().getValue()}
   */
  @PostMapping("/SpringSpelInjection/review-search")
  public @ResponseBody AttackResult reviewSearch(
      @RequestParam String employeeId,
      @RequestParam String reviewYear,
      @RequestParam String department,
      @RequestParam String outputView) {

    log.info(
        "SpEL injection lesson: employeeId='{}', reviewYear='{}', dept='{}', outputView='{}'",
        employeeId, reviewYear, department, outputView);

    // Safe parameters — handled as plain strings, never evaluated.
    String safeDisplay =
        String.format(
            "Employee: %s | Year: %s | Dept: %s",
            sanitise(employeeId), sanitise(reviewYear), sanitise(department));

    // VULNERABLE: outputView is passed directly to SpelExpressionParser without any validation.
    // This mirrors the pattern from https://techtalkpine.com/2025/04/spel-injection-demo/
    try {
      Object spelResult = parser.parseExpression(outputView).getValue();
      String resultStr = spelResult == null ? "null" : spelResult.toString();

      return failed(this)
          .output(safeDisplay + " | View: " + resultStr)
          .build();

    } catch (Exception ex) {
      return failed(this)
          .output(safeDisplay + " | View: " + outputView)
          .build();
    }
  }

  /**
   * Assignment endpoint — validates the submitted challenge token.
   *
   * <p>The token must be obtained by executing SpEL injection on {@code /review-search} and
   * calling {@link #getToken()} server-side. A correct submission proves that arbitrary code was
   * executed on the server.
   */
  @PostMapping("/SpringSpelInjection/submit-token")
  public @ResponseBody AttackResult submitToken(@RequestParam String token) {
    if (token == null || token.isBlank()) {
      return failed(this).feedback("spel-injection.token-empty").build();
    }
    if (CHALLENGE_TOKEN.equalsIgnoreCase(token.trim())) {
      return success(this).feedback("spel-injection.success").build();
    }
    return failed(this).feedback("spel-injection.wrong-token").build();
  }

  /** Strips characters that should not appear in safe display strings. */
  private static String sanitise(String value) {
    return value == null ? "" : value.replaceAll("[<>\"'&]", "");
  }
}
