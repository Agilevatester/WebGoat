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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
/**
 * Lesson endpoint for CVE-2022-22980 — Spring Data MongoDB SpEL injection.
 *
 * <p>The vulnerability lives in {@link CustomerRepository#findByFirstName}, annotated with
 * {@code @Query("{ 'firstName' : ?#{?0} }")}. The {@code ?#{...}} delimiter causes the real
 * {@code spring-data-mongodb:3.4.0} library to evaluate the caller-supplied argument as a SpEL
 * expression at query time via its {@code ExpressionEvaluatingParameterBinder}.
 *
 * <p>An attacker can pass a SpEL collection-selection expression such as
 * {@code ?[firstName != null]} to bypass the firstName equality filter and return every document in
 * the collection.
 *
 * <p>Flapdoodle embedded MongoDB provides an in-process MongoDB instance so the real 3rd-party
 * vulnerable code path executes end-to-end without an external server.
 *
 * <p>Reference: <a href="https://security.snyk.io/vuln/SNYK-JAVA-ORGSPRINGFRAMEWORKDATA-2932975">
 * SNYK-JAVA-ORGSPRINGFRAMEWORKDATA-2932975</a>
 */

@RestController
@AssignmentHints({"vulnerable-spring-mongodb.hint"})
public class VulnerableSpringMongoDBComponentsLesson extends AssignmentEndpoint {

  private static final Logger log =
      LoggerFactory.getLogger(VulnerableSpringMongoDBComponentsLesson.class);

  @Autowired(required = false)
  private CustomerRepository repository;

  // https://security.snyk.io/vuln/SNYK-JAVA-ORGSPRINGFRAMEWORKDATA-2932975
  @PostMapping("/VulnerableSpringMongoDBComponents/search")
  public @ResponseBody AttackResult index(@RequestParam("name") String name) {

    log.info("CVE-2022-22980 request, name='{}'", name);

    if (repository == null) {
      return failed(this)
          .feedback("vulnerable-spring-mongodb-components.not-configured")
          .output("Embedded MongoDB did not start. Check Flapdoodle dependency.")
          .build();
    }

    try {
      // The real @Query("{ 'firstName' : ?#{?0} }") SpEL binding in spring-data-mongodb:3.4.0
      // evaluates the ?#{...} template. Passing a SpEL expression as the name parameter causes
      // the library to evaluate it — this is the CVE-2022-22980 code path.
      Customer customer = repository.findByFirstName(name);

      if (customer != null) {
        // Normal lookup succeeded — no injection.
        return failed(this)
            .feedback("vulnerable-spring-mongodb-components.fromXML")
            .feedbackArgs(name)
            .build();
      }

      return failed(this)
          .feedback("vulnerable-spring-mongodb-components.not-found")
          .output("No customer found for: " + name)
          .build();

    } catch (Exception ex) {
      // When SpEL injection is attempted, spring-data-mongodb:3.4.0 evaluates the expression
      // and then fails to bind the result back to a String query value — the exception bubbles
      // up from ExpressionEvaluatingParameterBinder. This is the proof of execution.
      Throwable root = ex;
      ex.printStackTrace();
      while (root.getCause() != null) root = root.getCause();

      boolean spelTriggered =
          root instanceof org.springframework.expression.EvaluationException
              || root instanceof org.springframework.expression.ParseException
              || ex.getClass().getName().contains("spel")
              || (ex.getMessage() != null && ex.getMessage().toLowerCase().contains("spel"));

      if (spelTriggered) {
        return success(this)
            .feedback("vulnerable-spring-mongodb-components.success")
            .output(
                "SpEL injection executed via the real spring-data-mongodb:3.4.0 @Query binding. "
                    + "The ExpressionEvaluatingParameterBinder evaluated your input as a SpEL "
                    + "expression — in a real deployment this achieves Remote Code Execution.")
            .build();
      }

      return failed(this)
          .feedback("vulnerable-spring-mongodb-components.close")
          .output(ex.getMessage())
          .build();
    }
  }
}
