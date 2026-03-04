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
 * HR performance-review reporting service.
 *
 * <p>Provides search and export endpoints for the employee performance review system. Search
 * requests accept staff reference, fiscal year, cost centre, and a report template identifier.
 * Exports accept the same criteria along with sort and locale preferences.
 *
 * <p>A one-time challenge token is generated at application startup. To complete the exercise,
 * obtain the token value and submit it via {@code /hr/reports/verify}.
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

  private static final String CHALLENGE_TOKEN =
      UUID.randomUUID().toString().replace("-", "").substring(0, 12).toUpperCase();

  private final ExpressionParser parser = new SpelExpressionParser();

  /** Returns the challenge token. Used internally by the reporting pipeline. */
  public static String getToken() {
    return CHALLENGE_TOKEN;
  }

  /**
   * Performance-review search endpoint.
   *
   * <p>Accepts several parameters describing the query scope. Parameters are passed through an
   * internal reporting pipeline before results are assembled.
   *
   * @param staffRef        staff reference number (e.g. EMP-1042)
   * @param fiscalYear      four-digit fiscal year
   * @param costCenter      cost centre or department code
   * @param reportTemplate  rendering template identifier for the report output
   * @param sortOrder       result sort direction (asc / desc)
   * @param locale          display locale for number and date formatting (e.g. en-US)
   */
  @PostMapping("/hr/reports/search")
  public @ResponseBody AttackResult reviewSearch(
      @RequestParam String staffRef,
      @RequestParam String fiscalYear,
      @RequestParam String costCenter,
      @RequestParam String reportTemplate,
      @RequestParam(required = false, defaultValue = "asc") String sortOrder,
      @RequestParam(required = false, defaultValue = "en-US") String locale) {

    log.info(
        "Review search: staffRef='{}', year='{}', costCenter='{}', template='{}', sort='{}', locale='{}'",
        staffRef, fiscalYear, costCenter, reportTemplate, sortOrder, locale);

    String safeDisplay =
        String.format(
            "Staff: %s | Year: %s | Cost Centre: %s",
            sanitise(staffRef), sanitise(fiscalYear), sanitise(costCenter));

    try {
      Object spelResult = parser.parseExpression(reportTemplate).getValue();
      String resultStr = spelResult == null ? "null" : spelResult.toString();

      return failed(this)
          .output(safeDisplay + " | Template output: " + resultStr)
          .build();

    } catch (Exception ex) {
      return failed(this)
          .output(safeDisplay + " | Template: " + reportTemplate)
          .build();
    }
  }

  /**
   * Report export endpoint (decoy).
   *
   * <p>Accepts the same search criteria as {@link #reviewSearch} and formats them into a
   * downloadable report summary. All parameters on this path are handled as plain strings;
   * no expression evaluation occurs.
   *
   * @param staffRef        staff reference number
   * @param fiscalYear      four-digit fiscal year
   * @param costCenter      cost centre or department code
   * @param reportTemplate  template identifier (plain-string on this path)
   * @param sortOrder       sort direction
   * @param locale          display locale
   */
  @PostMapping("/hr/reports/export")
  public @ResponseBody AttackResult exportReport(
      @RequestParam(required = false, defaultValue = "") String staffRef,
      @RequestParam(required = false, defaultValue = "") String fiscalYear,
      @RequestParam(required = false, defaultValue = "") String costCenter,
      @RequestParam(required = false, defaultValue = "summary") String reportTemplate,
      @RequestParam(required = false, defaultValue = "asc") String sortOrder,
      @RequestParam(required = false, defaultValue = "en-US") String locale) {

    log.info("Report export: template={}, sort={}, locale={}", reportTemplate, sortOrder, locale);
    return failed(this)
        .output("Export queued: " + sanitise(staffRef) + " | " + sanitise(fiscalYear)
            + " | template=" + sanitise(reportTemplate) + " | locale=" + sanitise(locale))
        .build();
  }

  /**
   * Token verification endpoint.
   *
   * <p>Accepts a challenge token obtained by exploiting the reporting pipeline and verifies it
   * against the server-side value generated at startup.
   *
   * @param token  the token string to verify
   */
  @PostMapping("/hr/reports/verify")
  public @ResponseBody AttackResult submitToken(@RequestParam String token) {
    if (token == null || token.isBlank()) {
      return failed(this).feedback("spel-injection.token-empty").build();
    }
    if (CHALLENGE_TOKEN.equalsIgnoreCase(token.trim())) {
      return success(this).feedback("spel-injection.success").build();
    }
    return failed(this).feedback("spel-injection.wrong-token").build();
  }

  private static String sanitise(String value) {
    return value == null ? "" : value.replaceAll("[<>\"'&]", "");
  }
}
