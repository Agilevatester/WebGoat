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

package org.owasp.webgoat.lessons.osscamelsnakeyaml;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.CamelContext;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.snakeyaml.SnakeYAMLDataFormat;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.model.dataformat.YAMLLibrary;
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
 * Integration route data processing endpoint.
 *
 * <p>Accepts route data documents and forwards them through a Camel marshalling
 * pipeline. A supplementary status endpoint accepts the same parameters and
 * returns the current route state without processing the document body.
 */
@RestController
@AssignmentHints({"vulnerable-camel-snakeyaml.hint"})
public class VulnerableCamelSnakeYamlComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(this.getClass().getName());

  /**
   * Processes route data through the Camel integration pipeline.
   *
   * @param routeData    the route data document body
   * @param routeName    logical route identifier (routing/audit only)
   * @param engineId     target engine identifier (routing/audit only)
   */
  @PostMapping("/integration/route-data")
  public @ResponseBody AttackResult processRouteData(
      @RequestParam String routeData,
      @RequestParam(required = false, defaultValue = "") String routeName,
      @RequestParam(required = false, defaultValue = "") String engineId) {

    log.info("Route data: routeName={}, engineId={}", routeName, engineId);

    try {
      CamelContext camelctx = new DefaultCamelContext();
      camelctx.addRoutes(
          new RouteBuilder() {
            @Override
            public void configure() throws Exception {
              from("direct:start").marshal().yaml(YAMLLibrary.SnakeYAML);
            }
          });

      ClassLoader loader = SnakeYAMLDataFormat.class.getClassLoader();
      loader = loader.loadClass("org.yaml.snakeyaml.Yaml").getClassLoader();
      log.info("yaml class loaded: {}", loader);
      camelctx.getTypeConverterRegistry().addTypeConverters(new Test1(new ObjectMapper()));
      camelctx.start();

      ProducerTemplate template = camelctx.createProducerTemplate();
      Test1 result = template.requestBody("direct:start", routeData, Test1.class);
    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-camel-snakeyaml-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-camel-snakeyaml-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-camel-snakeyaml-components.fromXML")
        .feedbackArgs(routeData)
        .build();
  }

  /**
   * Route status endpoint (decoy).
   *
   * <p>Returns the current operational status of the named route without
   * processing any document body.
   *
   * @param routeName    logical route identifier
   * @param engineId     target engine identifier
   */
  @PostMapping("/integration/route-status")
  public @ResponseBody AttackResult routeStatus(
      @RequestParam(required = false, defaultValue = "") String routeName,
      @RequestParam(required = false, defaultValue = "") String engineId) {

    return failed(this)
        .output("Route status: "
            + (routeName.isEmpty() ? "default" : routeName)
            + " — idle.")
        .build();
  }
}
