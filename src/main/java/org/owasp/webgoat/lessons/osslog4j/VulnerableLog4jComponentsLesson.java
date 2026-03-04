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

package org.owasp.webgoat.lessons.osslog4j;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Lesson endpoint: diagnostic event tracing for a REST-based monitoring service.
 *
 * <p>The service accepts tracing metadata from clients and writes structured log entries using the
 * application's shared logging pipeline. Fields include a severity level, target region, and a
 * free-form request tag used for cross-service correlation.
 *
 * <p>A secondary report-generation endpoint accepts the same set of parameters but processes them
 * through a separate, read-only reporting pipeline.
 */
@RestController
@AssignmentHints({"vulnerable-log4j.hint"})
public class VulnerableLog4jComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(VulnerableLog4jComponentsLesson.class.getName());

  /**
   * Primary diagnostic trace endpoint.
   *
   * <p>Accepts a traceability tag ({@code requestTag}) that is forwarded by client middleware as
   * the {@code X-Api-Version} request header for downstream version negotiation. The logging
   * pipeline records this header value for audit purposes.
   *
   * @param apiversion  value of the {@code X-Api-Version} request header, set by client middleware
   * @param traceLevel  severity level for the trace entry (INFO, WARN, DEBUG, TRACE)
   * @param serviceRegion  originating service region (e.g. us-east-1)
   * @param requestTag  free-form correlation tag; client middleware forwards this as X-Api-Version
   */
  @PostMapping("/api/diagnostics/trace")
  public @ResponseBody AttackResult index(
      @RequestHeader(name = "X-Api-Version", required = false) String apiversion,
      @RequestParam(required = false, defaultValue = "INFO") String traceLevel,
      @RequestParam(required = false, defaultValue = "us-east-1") String serviceRegion,
      @RequestParam(required = false, defaultValue = "") String requestTag) {

    try {
      log.info("Diagnostic trace: level={}, region={}", traceLevel, serviceRegion);
      log.info("Received a request for API version: {}", apiversion);

      if (isJndiLookupPattern(apiversion)) {
        return success(this)
            .feedback("vulnerable-log4j-components.success")
            .output("Diagnostic trace captured an unexpected lookup directive in the request: " + apiversion)
            .build();
      }

      if (isJndiLookupPattern(requestTag)) {
        return failed(this)
            .feedback("vulnerable-log4j-components.fromXML")
            .output("Request tag contained a lookup directive: " + requestTag)
            .build();
      }

    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-log4j-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-log4j-components.fromXML")
        .feedbackArgs(requestTag)
        .build();
  }

  /**
   * Report-generation endpoint (decoy).
   *
   * <p>Accepts the same tracing parameters as {@link #index} but writes them through the
   * read-only reporting pipeline. No log interpolation occurs on the report path.
   *
   * @param traceLevel   severity level filter for the report
   * @param serviceRegion  region scope for the report
   * @param requestTag   correlation tag to include in the report header
   */
  @PostMapping("/api/diagnostics/report")
  public @ResponseBody AttackResult generateReport(
      @RequestParam(required = false, defaultValue = "INFO") String traceLevel,
      @RequestParam(required = false, defaultValue = "us-east-1") String serviceRegion,
      @RequestParam(required = false, defaultValue = "") String requestTag) {

    log.info("Diagnostic report: level={}, region={}", traceLevel, serviceRegion);
    return failed(this)
        .output("Report generated. Trace level: " + traceLevel + " | Region: " + serviceRegion)
        .build();
  }

  private boolean isJndiLookupPattern(String input) {
    if (input == null || input.trim().isEmpty()) {
      return false;
    }

    String lower = input.toLowerCase();

    boolean hasJndiSyntax  = lower.contains("${jndi:");
    boolean hasLdapScheme  = lower.contains("ldap://") || lower.contains("ldaps://");
    boolean hasDirectLdap  = lower.contains("jndi:ldap") || lower.contains("jndi:rmi");

    return (hasJndiSyntax && hasLdapScheme) || hasDirectLdap;
  }
}
