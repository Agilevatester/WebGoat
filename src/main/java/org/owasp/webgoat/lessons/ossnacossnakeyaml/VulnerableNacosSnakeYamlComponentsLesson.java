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

package org.owasp.webgoat.lessons.ossnacossnakeyaml;

import com.alibaba.nacos.spring.util.parse.DefaultYamlConfigParse;
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
 * Nacos configuration synchronisation service.
 *
 * <p>Accepts configuration documents for synchronisation into a Nacos-backed configuration store.
 * Documents are scoped by namespace and group. A separate diff endpoint accepts the same
 * parameters and returns a comparison summary without performing any synchronisation.
 */
@RestController
@AssignmentHints({"vulnerable-nacos-snakeyaml.hint"})
public class VulnerableNacosSnakeYamlComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(this.getClass().getName());

  /**
   * Synchronises a configuration document into the Nacos configuration store.
   *
   * <p>The document is parsed using the Nacos {@link DefaultYamlConfigParse} and the resulting
   * object graph is inspected before persistence. Namespace and group parameters scope the target
   * configuration data id within the store.
   *
   * @param configBody   raw configuration document body
   * @param namespace    Nacos namespace identifier (display/routing only)
   * @param group        Nacos configuration group name (display/routing only)
   */
  @PostMapping("/config/sync")
  public @ResponseBody AttackResult NacosYamlParser(
      @RequestParam String configBody,
      @RequestParam(required = false, defaultValue = "public") String namespace,
      @RequestParam(required = false, defaultValue = "DEFAULT_GROUP") String group) {

    log.info("Config sync: namespace={}, group={}", namespace, group);

    try {
      DefaultYamlConfigParse yaml = new DefaultYamlConfigParse();
      Object obj = yaml.parse(configBody).get("document");

      if (obj instanceof javax.script.ScriptEngineManager) {
        return success(this)
            .feedback("vulnerable-nacos-snakeyaml-components.success")
            .output(obj.getClass().toString())
            .build();
      }
    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-nacos-snakeyaml-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-nacos-snakeyaml-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-nacos-snakeyaml-components.fromXML")
        .feedbackArgs(configBody)
        .build();
  }

  /**
   * Compares a configuration document against the stored version (decoy).
   *
   * <p>Accepts the same parameters as {@link #NacosYamlParser} but does not persist or
   * deserialize the document. Returns a simple diff summary indicating key-level additions
   * and removals.
   *
   * @param configBody   raw configuration document body for comparison
   * @param namespace    Nacos namespace identifier
   * @param group        Nacos configuration group name
   */
  @PostMapping("/config/diff")
  public @ResponseBody AttackResult configDiff(
      @RequestParam(required = false, defaultValue = "") String configBody,
      @RequestParam(required = false, defaultValue = "public") String namespace,
      @RequestParam(required = false, defaultValue = "DEFAULT_GROUP") String group) {

    log.info("Config diff: namespace={}, group={}, size={}", namespace, group, configBody.length());
    return failed(this)
        .output("Diff complete: namespace=" + namespace + ", group=" + group
            + ", document size=" + configBody.length() + " bytes")
        .build();
  }
}

class NacosConfigRecord {
  public String some_var = "default";

  public String getSome_var() {
    return some_var;
  }

  public void setSome_var(String some_var) {
    this.some_var = some_var;
  }
}
