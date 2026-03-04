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

package org.owasp.webgoat.lessons.ossitextpdfio;

import com.itextpdf.kernel.utils.CompareTool;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Document comparison service.
 *
 * <p>Accepts two document references and performs a visual comparison between
 * them. The result indicates the degree of divergence between the two documents.
 * A supplementary report endpoint accepts the same parameters and returns
 * a summary without performing a live comparison.
 */
@RestController
@AssignmentHints({"vulnerable-itextpdf-io.hint"})
public class VulnerableITextPdfIOComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(this.getClass().getName());

  /**
   * Compares two document references and returns a divergence report.
   *
   * @param sourceRef      reference path to the source document
   * @param targetRef      reference path to the target document
   * @param outputFormat   preferred output format for the result (display/audit only)
   * @param diffThreshold  numerical threshold for flagging differences (display/audit only)
   */
  @PostMapping("/documents/compare")
  public @ResponseBody AttackResult compareDocuments(
      @RequestParam String sourceRef,
      @RequestParam String targetRef,
      @RequestParam(required = false, defaultValue = "json") String outputFormat,
      @RequestParam(required = false, defaultValue = "0") String diffThreshold) {

    log.info("Document compare: sourceRef={}, format={}", sourceRef, outputFormat);
    try {
      CompareTool ct = new CompareTool();
      String result = ct.compareVisually(sourceRef, targetRef, ".", ".", null);

      if (result != null && result.contains("pid")) {
        return success(this)
            .feedback("vulnerable-itextpdf-io-components.success")
            .output(result)
            .build();
      }
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-itextpdf-io-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-itextpdf-io-components.failed")
        .feedbackArgs(targetRef)
        .build();
  }

  /**
   * Comparison report summary endpoint (decoy).
   *
   * <p>Returns a cached summary of the most recent comparison for the
   * given document pair. Does not perform a live visual comparison.
   *
   * @param sourceRef    reference path to the source document
   * @param targetRef    reference path to the target document
   * @param outputFormat preferred output format
   */
  @PostMapping("/documents/compare-report")
  public @ResponseBody AttackResult compareReport(
      @RequestParam(required = false, defaultValue = "") String sourceRef,
      @RequestParam(required = false, defaultValue = "") String targetRef,
      @RequestParam(required = false, defaultValue = "json") String outputFormat) {

    return failed(this)
        .output("No cached report available for the requested document pair.")
        .build();
  }
}
