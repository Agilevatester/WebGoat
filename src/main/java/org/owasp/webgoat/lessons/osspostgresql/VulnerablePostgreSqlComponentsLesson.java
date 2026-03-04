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

package org.owasp.webgoat.lessons.osspostgresql;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
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
 * Inventory management query service.
 *
 * <p>Exposes endpoints for querying the inventory data store and for configuring the JDBC connector
 * used by the data access layer. A read-only statistics endpoint is also provided for dashboard use.
 */
@RestController
@AssignmentHints({"vulnerable-postgresql.hint"})
public class VulnerablePostgreSqlComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(VulnerablePostgreSqlComponentsLesson.class.getName());

  /**
   * Queries inventory records by login count and account reference.
   *
   * <p>Accepts a numeric login count and an account reference string to scope the query.
   * An optional category filter is accepted for display purposes.
   *
   * @param count       login count filter (numeric)
   * @param accountRef  account reference identifier
   * @param category    inventory category label (display only)
   */
  @PostMapping("/inventory/query")
  public @ResponseBody AttackResult index(
      @RequestParam("count") Integer count,
      @RequestParam("accountRef") String accountRef,
      @RequestParam(required = false, defaultValue = "") String category) {

    log.info("Inventory query: count={}, category={}", count, category);

    String queryString = "SELECT * From user_data WHERE Login_Count = ? and userid= ?";
    try (Connection connection = PostgreSqlConnector.getDriverConnection()) {
      PreparedStatement query = connection.prepareStatement(queryString);
      query.setInt(1, count);
      query.setString(2, accountRef);

      try {
        ResultSet results = query.executeQuery();

        if ((results != null) && (results.first() == true)) {
          ResultSetMetaData resultsMetaData = results.getMetaData();
          StringBuilder output = new StringBuilder();

          output.append(writeTable(results, resultsMetaData));
          results.last();

          if (results.getRow() > 1 && count == -1) {
            return success(this)
                .feedback("postgresql-injection.success")
                .output(
                    "Your query was: "
                        + queryString.replace("?", count.toString()).replace("?", accountRef))
                .feedbackArgs(output.toString())
                .build();
          } else {
            return failed(this)
                .output(
                    output.toString()
                        + "<br> Your query was: "
                        + queryString.replace("?", count.toString()).replace("?", accountRef))
                .build();
          }

        } else {
          return failed(this)
              .feedback("postgresql-injection.no.results")
              .output(
                  "Your query was: "
                      + queryString.replace("?", count.toString()).replace("?", accountRef))
              .build();
        }
      } catch (SQLException sqle) {
        return failed(this)
            .output(
                sqle.getMessage()
                    + "<br> Your query was: "
                    + queryString.replace("?", count.toString()).replace("?", accountRef))
            .build();
      }

    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-postgresql-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-postgresql-components.close")
          .output(ex.getMessage())
          .build();
    }
  }

  /**
   * Configures the JDBC connector with a custom driver path.
   *
   * <p>Accepts a connector path that is used to initialise the PostgreSQL JDBC driver.
   * This endpoint is intended for use by operations teams reconfiguring the data access layer.
   *
   * @param connectorPath  JDBC driver path or connection string override
   */
  @PostMapping("/db/driver/configure")
  public @ResponseBody AttackResult configure(@RequestParam("connectorPath") String connectorPath) {

    log.info("DB driver configure: connectorPath='{}'", connectorPath);

    try (Connection connection = PostgreSqlConnector.getDriverConnection(connectorPath)) {

      if (!connection.isClosed()) {
        return success(this)
            .feedback("postgresql-injection.success")
            .output("Connector configured: ")
            .feedbackArgs(connectorPath)
            .build();
      } else {
        return failed(this).output("<br> Connector path: " + connectorPath).build();
      }

    } catch (SQLException sqle) {
      return failed(this).output(sqle.getMessage() + "<br> Connector path: " + connectorPath).build();
    } catch (ClassNotFoundException sqle) {
      return failed(this).output(sqle.getMessage() + "<br> Connector path: " + connectorPath).build();
    }
  }

  /**
   * Returns aggregated inventory statistics (decoy).
   *
   * <p>Accepts a category and account reference for scoping and returns a static summary.
   * No dynamic query execution or JDBC connection occurs on this path.
   *
   * @param category    inventory category for the summary
   * @param accountRef  account reference to scope the statistics
   */
  @PostMapping("/inventory/stats")
  public @ResponseBody AttackResult inventoryStats(
      @RequestParam(required = false, defaultValue = "all") String category,
      @RequestParam(required = false, defaultValue = "") String accountRef) {

    log.info("Inventory stats: category={}", category);
    return failed(this)
        .output("Stats: category=" + category + ", scope=" + (accountRef.isEmpty() ? "global" : accountRef))
        .build();
  }

  private static String writeTable(ResultSet results, ResultSetMetaData resultsMetaData)
      throws SQLException {
    int numColumns = resultsMetaData.getColumnCount();
    results.beforeFirst();
    StringBuilder t = new StringBuilder();
    t.append("<p>");

    if (results.next()) {
      for (int i = 1; i < (numColumns + 1); i++) {
        t.append(resultsMetaData.getColumnName(i));
        t.append(", ");
      }

      t.append("<br />");
      results.beforeFirst();

      while (results.next()) {
        for (int i = 1; i < (numColumns + 1); i++) {
          t.append(results.getString(i));
          t.append(", ");
        }
        t.append("<br />");
      }

    } else {
      t.append("Query Successful; however no data was returned from this query.");
    }

    t.append("</p>");
    return (t.toString());
  }
}
