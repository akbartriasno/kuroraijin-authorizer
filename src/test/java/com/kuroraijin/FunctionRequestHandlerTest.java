package com.kuroraijin;

//import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
//import jakarta.inject.Inject;
//import org.junit.jupiter.api.Test;
//
//import java.util.HashMap;
//import java.util.Map;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.junit.jupiter.api.Assertions.assertNotNull;

//@MicronautTest(environments = "test")
public class FunctionRequestHandlerTest {

//    @Inject
//    CoreAuthorizerHandler handler;
//
//    @Test
//    void shouldAllowWithValidToken() {
//        Map<String, Object> event = new HashMap<>();
//        Map<String, Object> headers = new HashMap<>();
//        headers.put("Authorization", "Bearer " + "<ACCESS_TOKEN_VALID_KAMU>");
//        event.put("headers", headers);
//        event.put("type", "REQUEST");
//        event.put("methodArn", "arn:aws:execute-api:ap-southeast-3:730335295088:apiId/dev/GET/hello");
//
//        Map<String, Object> result = handler.execute(event);
//
//        assertNotNull(result);
//        Map<String, Object> policy = (Map<String, Object>) result.get("policyDocument");
//        assertNotNull(policy);
//        assertEquals("2012-10-17", policy.get("Version"));
//        // dst… assert Effect=Allow, Resource berisi daftar ARN, dll
//    }
//
//    @Test
//    void shouldDenyWithoutToken() {
//        Map<String, Object> event = new HashMap<>();
//        Map<String, Object> result = handler.execute(event);
//        Map<String, Object> policy = (Map<String, Object>) result.get("policyDocument");
//        var stmts = (java.util.List<Map<String,Object>>) policy.get("Statement");
//        assertEquals("Deny", stmts.get(0).get("Effect"));
//    }
}
