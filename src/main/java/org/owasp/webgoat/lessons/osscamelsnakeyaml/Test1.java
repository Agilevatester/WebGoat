package org.owasp.webgoat.lessons.osscamelsnakeyaml;

import java.io.IOException;
import java.util.Map;

import org.apache.camel.Converter;
import org.apache.camel.TypeConverters;
import org.springframework.beans.factory.annotation.Autowired;
import org.yaml.snakeyaml.Yaml;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@Converter
public class Test1 implements TypeConverters {
    public String some_var = "abc";

    public String getSome_var() {
        return some_var;
    }

    public void setSome_var(String some_var) {
        this.some_var = some_var;
    }

    private final ObjectMapper mapper;

    @Autowired
    public Test1(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public Test1() {
        this.mapper = new ObjectMapper(); // Initialize the ObjectMapper

    }

    @Converter
    public byte[] myPackageToByteArray(Test1 source) {
        try {
            return mapper.writeValueAsBytes(source);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Converter
    public Test1 byteArrayToMyPackage(byte[] source) {
        try {
            Yaml yaml = new Yaml();
            Object data = yaml.load(new String(source));

        if (data instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) data;
            Test1 test1 = new Test1();
            test1.setSome_var((String) map.get("some_var"));
            return test1;
        } else if (data instanceof String) {
            // Handle case where YAML is parsed as a plain string
            Test1 test1 = new Test1();
            test1.setSome_var((String) data);
            return test1;
        } else {
            throw new RuntimeException("Invalid YAML payload: Expected a Map or String but got " + data.getClass().getSimpleName());
        }
        } catch (Exception e) {
            throw new RuntimeException("Error parsing YAML payload", e);
        }
    }
    // @Converter
    // public Test1 byteArrayToMyPackageold(byte[] source) {
    // try {
    // return mapper.readValue(source, Test1.class);
    // } catch (IOException e) {
    // throw new RuntimeException(e);
    // }
    // }
}
