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

package org.owasp.webgoat.lessons.ossverapdfcorejakarta;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.verapdf.core.VeraPDFException;
import org.verapdf.policy.PolicyChecker;

/**
 * Document policy evaluation endpoint.
 *
 * <p>Applies a submitted policy document to a PDF compliance check workflow.
 * The policy document is evaluated by the PDF policy processor and the result
 * is returned to the caller. A separate history endpoint accepts the same
 * parameters and returns metadata about previously applied policies without
 * performing live evaluation.
 */
@RestController
@AssignmentHints({"vulnerable-verapdf.hint"})
public class VulnerableVeraPdfCoreJakartaComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(this.getClass().getName());

  /**
   * Applies a policy document to the PDF compliance checker.
   *
   * @param policyDocument  the policy document body to evaluate
   * @param validateSchema  whether to treat the document as a stylesheet (true/false)
   * @param documentId      document reference identifier (routing/audit only)
   * @param outputFormat    preferred result format (display/audit only)
   */
  @PostMapping("/documents/policy-check")
  public @ResponseBody AttackResult applyDocumentPolicy(
      @RequestParam String policyDocument,
      @RequestParam(required = false, defaultValue = "false") Boolean validateSchema,
      @RequestParam(required = false, defaultValue = "") String documentId,
      @RequestParam(required = false, defaultValue = "json") String outputFormat) {

    log.info("Policy check: documentId={}, format={}", documentId, outputFormat);
    try {

      InputStream is = new ByteArrayInputStream(policyDocument.getBytes(StandardCharsets.UTF_8));
      OutputStream policyResultOss =
          new OutputStream() {
            StringBuilder sb = new StringBuilder();

            @Override
            public void write(int b) throws IOException {
              this.sb.append((char) b);
            }

            public String toString() {
              return this.sb.toString();
            }
          };
      PolicyChecker.applyPolicy(
          new ByteArrayInputStream(policyDocument.getBytes(StandardCharsets.UTF_8)),
          is,
          policyResultOss,
          validateSchema);

      if (policyResultOss.toString().contains("pid")) {
        return success(this)
            .feedback("vulnerable-verapdf-components.success")
            .output(policyResultOss.toString())
            .build();
      }
    } catch (VeraPDFException ex) {
      return success(this)
          .feedback("vulnerable-verapdf-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-verapdf-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-verapdf-components.fromXML")
        .feedbackArgs(policyDocument)
        .build();
  }

  /**
   * Policy history retrieval endpoint (decoy).
   *
   * <p>Returns metadata about the most recently applied policy for the given
   * document. Does not evaluate the supplied document body.
   *
   * @param documentId      document reference identifier
   * @param outputFormat    preferred result format
   */
  @PostMapping("/documents/policy-history")
  public @ResponseBody AttackResult policyHistory(
      @RequestParam(required = false, defaultValue = "") String documentId,
      @RequestParam(required = false, defaultValue = "json") String outputFormat) {

    return failed(this)
        .output("No policy history found for document"
            + (documentId.isEmpty() ? "." : " '" + documentId + "'."))
        .build();
  }
}
