package org.owasp.webgoat.lessons.osscamelsnakeyaml;

import java.util.HashMap;
import java.util.Map;
import org.apache.camel.CamelContext;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.component.snakeyaml.SnakeYAMLDataFormat;
// import org.junit.jupiter.api.Assertions;
import org.yaml.snakeyaml.nodes.Tag;

public final class SnakeYAMLTestHelper {
//Camel Sample Raw
  protected SnakeYAMLTestHelper() {}

  public static UnsafePojo createTestPojo() {
    return new UnsafePojo("Camel");
  }

  public static Map<String, String> createTestMap() {
    Map<String, String> map = new HashMap<>();
    map.put("name", "Camel");

    return map;
  }

  public static SnakeYAMLDataFormat createDataFormat(final Class<?> type) {
    SnakeYAMLDataFormat format = new SnakeYAMLDataFormat();
    if (type != null) {
      format.setUnmarshalType(type);
    }

    return format;
  }

  public static SnakeYAMLDataFormat createPrettyFlowDataFormat(Class<?> type, boolean prettyFlow) {
    SnakeYAMLDataFormat format = createDataFormat(type);
    format.setPrettyFlow(prettyFlow);

    return format;
  }

  public static SnakeYAMLDataFormat createClassTagDataFormat(Class<?> type, Tag tag) {
    SnakeYAMLDataFormat format = createDataFormat(type);
    format.addTag(type, tag);

    return format;
  }

  public static void marshalAndUnmarshal(
      CamelContext context,
      Object body,
      String mockName,
      String directIn,
      String directBack,
      String expected)
      throws Exception {

    MockEndpoint mock = context.getEndpoint(mockName, MockEndpoint.class);
    //	  Assertions.assertNotNull(mock);

    mock.expectedMessageCount(1);
    mock.message(0).body().isInstanceOf(body.getClass());
    mock.message(0).body().isEqualTo(body);

    ProducerTemplate template = context.createProducerTemplate();
    String result = template.requestBody(directIn, body, String.class);
    //	  Assertions.assertNotNull(result);
    //	  Assertions.assertEquals(expected, result.trim());

    template.sendBody(directBack, result);

    mock.assertIsSatisfied();
  }
}
