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

package org.owasp.webgoat.lessons.ossspringmongodb;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.quartz.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable-spring-mongodb.hint"})
public class VulnerableSpringMongoDBComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(VulnerableSpringMongoDBComponentsLesson.class.getName());

  //   @Autowired
  private CustomerRepository repository;

  // https://security.snyk.io/vuln/SNYK-JAVA-ORGSPRINGFRAMEWORKDATA-2932975
  @PostMapping("/VulnerableSpringMongoDBComponentsLesson/CVE-2022-22980")
  public @ResponseBody AttackResult index(@RequestParam("name") String name) {

    try {
      log.info(
          "Received a request for VulnerableSpringMongoDBComponentsLesson/CVE-2022-22980 : {}",
          name);
      // https://github.com/trganda/CVE-2022-22980/blob/main/src/main/java/com/example/accessingdatamongodb/CustomerRepository.java
      Customer customer = repository.findByFirstName(name);

      if (name != null && customer == null) {
        success(this)
            .feedback("vulnerable-spring-mongodb-components.success")
            .output("Successfully exploited ")
            .build();
      }

    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-spring-mongodb-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-spring-mongodb-components.fromXML")
        .feedbackArgs(name)
        .build();
  }

  public static void main(String[] args) throws Exception {}

  public static class HelloJob implements Job {
    Logger log = LoggerFactory.getLogger(HelloJob.class.getName());

    @Override
    public void execute(JobExecutionContext jobExecutionContext) throws JobExecutionException {
      log.info("HelloJob executed");
      System.out.println(" Job Scheduler");
      System.out.println(
          "Job Details Map --> "
              + jobExecutionContext.getJobDetail().getJobDataMap().getString("jobId"));
      //      jobExecutionContext.getJobDetail().getJobDataMap()

    }
  }
}
