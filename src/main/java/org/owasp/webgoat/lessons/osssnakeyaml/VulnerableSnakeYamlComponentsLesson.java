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

/**
 * Configuration import service backed by YAML parsing.
 *
 * <p>The service exposes several endpoints that accept configuration documents in YAML format.
 * Each endpoint uses a different constructor strategy, providing varying levels of type resolution
 * control. A preview endpoint allows clients to inspect parsed key counts before committing an
 * import.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code /config/import}           — full constructor import (primary path)</li>
 *   <li>{@code /config/validate}         — schema-validation import using loadAs</li>
 *   <li>{@code /config/safe-import}      — SafeConstructor-protected import</li>
 *   <li>{@code /config/restricted-import}— allowlist-restricted type import</li>
 *   <li>{@code /config/preview}          — dry-run preview using SafeConstructor (decoy)</li>
 * </ul>
 */
@RestController
@AssignmentHints({"vulnerable-snakeyaml.hint"})
public class VulnerableSnakeYamlComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(this.getClass().getName());

  /**
   * Imports a YAML configuration document using the full {@link Constructor}.
   *
   * <p>Accepts an optional {@code importFormat} hint (csv, json, yaml) for client-side format
   * selection display, and an {@code environment} label (production, staging, development) for
   * audit tagging. Only the {@code configData} body is parsed.
   *
   * @param configData    raw YAML document body
   * @param importFormat  format identifier from the client UI (display only)
   * @param environment   target environment label (display only)
   */
  @PostMapping("/config/import")
  public @ResponseBody AttackResult ConstructorWithload(
      @RequestParam String configData,
      @RequestParam(required = false, defaultValue = "yaml") String importFormat,
      @RequestParam(required = false, defaultValue = "production") String environment) {

    log.info("Config import: format={}, env={}, size={}", importFormat, environment, configData.length());

    Yaml yaml = new Yaml(new Constructor(ConfigRecord.class));

    try {
      Map<String, Object> obj = yaml.load(configData);

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
        .feedbackArgs(configData)
        .build();
  }

  /**
   * Validates a YAML configuration document using {@code loadAs}.
   *
   * <p>Uses the same {@link Constructor} as {@link #ConstructorWithload} but invokes
   * {@code loadAs(Map.class)} for explicit type binding during schema validation.
   *
   * @param configData    raw YAML document body
   * @param importFormat  format identifier from the client UI (display only)
   */
  @PostMapping("/config/validate")
  public @ResponseBody AttackResult ConstructorWithloadAs(
      @RequestParam String configData,
      @RequestParam(required = false, defaultValue = "yaml") String importFormat) {

    log.info("Config validate: format={}", importFormat);

    Yaml yaml = new Yaml(new Constructor(ConfigRecord.class));

    try {
      Map<String, Object> obj = yaml.loadAs(configData, Map.class);

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
        .feedbackArgs(configData)
        .build();
  }

  /**
   * Imports a YAML document using {@link SafeConstructor}.
   *
   * <p>This endpoint demonstrates the mitigation: {@link SafeConstructor} refuses to instantiate
   * arbitrary Java types via YAML type tags, restricting deserialization to standard scalars,
   * sequences, and mappings.
   *
   * @param configData    raw YAML document body
   * @param importFormat  format identifier from the client UI (display only)
   */
  @PostMapping("/config/safe-import")
  public @ResponseBody AttackResult safeConstructor(
      @RequestParam String configData,
      @RequestParam(required = false, defaultValue = "yaml") String importFormat) {

    log.info("Safe config import: format={}", importFormat);

    var loaderOptions = new LoaderOptions();
    Yaml yaml = new Yaml(new SafeConstructor(loaderOptions));

    try {
      Map<String, Object> obj = yaml.loadAs(configData, Map.class);

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
        .feedbackArgs(configData)
        .build();
  }

  /**
   * Imports a YAML document using a type-allowlist constructor.
   *
   * <p>Extends {@link Constructor} with an override of {@link Constructor#getClassForName} that
   * permits only {@code java.util.List} and {@code java.util.Map}. Any other fully-qualified class
   * name referenced via a YAML type tag is rejected with an {@link IllegalStateException}.
   *
   * @param configData    raw YAML document body
   * @param importFormat  format identifier from the client UI (display only)
   */
  @PostMapping("/config/restricted-import")
  public @ResponseBody AttackResult restrictConstructor(
      @RequestParam String configData,
      @RequestParam(required = false, defaultValue = "yaml") String importFormat) {

    log.info("Restricted config import: format={}", importFormat);

    Yaml yaml = new Yaml(new AllowlistConstructor());

    try {
      Map<String, Object> obj = yaml.loadAs(configData, Map.class);

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
        .feedbackArgs(configData)
        .build();
  }

  /**
   * Dry-run preview endpoint (decoy).
   *
   * <p>Parses the supplied document with {@link SafeConstructor} and returns a count of top-level
   * keys without persisting anything. Intended for client-side preview before committing an import.
   * No unsafe type resolution occurs on this path.
   *
   * @param configData    raw YAML document body
   * @param importFormat  format identifier from the client UI (display only)
   * @param environment   target environment label for the preview header (display only)
   */
  @PostMapping("/config/preview")
  public @ResponseBody AttackResult previewConfig(
      @RequestParam String configData,
      @RequestParam(required = false, defaultValue = "yaml") String importFormat,
      @RequestParam(required = false, defaultValue = "development") String environment) {

    log.info("Config preview: format={}, env={}", importFormat, environment);

    var loaderOptions = new LoaderOptions();
    Yaml yaml = new Yaml(new SafeConstructor(loaderOptions));

    try {
      Map<String, Object> obj = yaml.loadAs(configData, Map.class);
      int keyCount = (obj == null) ? 0 : obj.size();
      return failed(this)
          .output("Preview: parsed " + keyCount + " top-level key(s) in "
              + importFormat + " format [" + environment + "]")
          .build();
    } catch (Exception ex) {
      return failed(this)
          .output("Preview failed: " + ex.getMessage())
          .build();
    }
  }

  private static class AllowlistConstructor extends Constructor {

    private static final Set<String> ALLOWED_TYPES;

    static {
      Set<Class<?>> allowed = new LinkedHashSet<>();
      allowed.add(List.class);
      allowed.add(Map.class);
      ALLOWED_TYPES =
          allowed.stream()
              .map(Class::getName)
              .collect(
                  Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
    }

    @Override
    protected Class<?> getClassForName(String name) throws ClassNotFoundException {
      Assert.state(
          ALLOWED_TYPES.contains(name),
          () -> "Unsupported '" + name + "' type encountered in configuration document");
      return super.getClassForName(name);
    }
  }
}

class ConfigRecord {
  public String some_var = "default";

  public String getSome_var() {
    return some_var;
  }

  public void setSome_var(String some_var) {
    this.some_var = some_var;
  }
}
