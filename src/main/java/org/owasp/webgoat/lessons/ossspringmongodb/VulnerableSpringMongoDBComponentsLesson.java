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
 * Customer directory lookup service.
 *
 * <p>Provides two endpoints for querying customer records. The primary lookup endpoint accepts a
 * search term and optional sort and pagination parameters. A separate profile endpoint retrieves a
 * static summary by account identifier.
 */
@RestController
@AssignmentHints({"vulnerable-spring-mongodb.hint"})
public class VulnerableSpringMongoDBComponentsLesson extends AssignmentEndpoint {

  private static final Logger log =
      LoggerFactory.getLogger(VulnerableSpringMongoDBComponentsLesson.class);

  @Autowired(required = false)
  private CustomerRepository repository;

  /**
   * Searches the customer directory by first name.
   *
   * <p>Accepts a search term along with optional sort and pagination hints. The search term is
   * forwarded to the repository query binding for evaluation.
   *
   * @param searchTerm  customer first name to search for
   * @param sortField   field to sort results by (display only)
   * @param maxResults  maximum number of results to return (display only)
   */
  @PostMapping("/customers/lookup")
  public @ResponseBody AttackResult index(
      @RequestParam("searchTerm") String searchTerm,
      @RequestParam(required = false, defaultValue = "lastName") String sortField,
      @RequestParam(required = false, defaultValue = "10") String maxResults) {

    log.info("Customer lookup: term='{}', sort='{}', max='{}'", searchTerm, sortField, maxResults);

    if (repository == null) {
      return failed(this)
          .feedback("vulnerable-spring-mongodb-components.not-configured")
          .output("Embedded MongoDB did not start. Check Flapdoodle dependency.")
          .build();
    }

    try {
      Customer customer = repository.findByFirstName(searchTerm);

      if (customer != null) {
        return failed(this)
            .feedback("vulnerable-spring-mongodb-components.fromXML")
            .feedbackArgs(searchTerm)
            .build();
      }

      return failed(this)
          .feedback("vulnerable-spring-mongodb-components.not-found")
          .output("No customer found for: " + searchTerm)
          .build();

    } catch (Exception ex) {
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
                "Query binding evaluated the supplied term as an expression. "
                    + "In a real deployment this execution path achieves Remote Code Execution.")
            .build();
      }

      return failed(this)
          .feedback("vulnerable-spring-mongodb-components.close")
          .output(ex.getMessage())
          .build();
    }
  }

  /**
   * Retrieves a static customer profile by account identifier (decoy).
   *
   * <p>This endpoint does not perform dynamic query binding. It accepts an account identifier and
   * account type and returns a fixed profile summary. No expression evaluation occurs on this path.
   *
   * @param customerId   account identifier
   * @param accountType  account tier (standard, premium, enterprise)
   */
  @PostMapping("/customers/profile")
  public @ResponseBody AttackResult getProfile(
      @RequestParam(required = false, defaultValue = "") String customerId,
      @RequestParam(required = false, defaultValue = "standard") String accountType) {

    log.info("Customer profile: id='{}', type='{}'", customerId, accountType);
    return failed(this)
        .output("Profile retrieved for account: " + customerId + " [" + accountType + "]")
        .build();
  }
}
