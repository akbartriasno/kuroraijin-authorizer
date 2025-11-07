package com.kuroraijin.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PolicyDocumentUtil {

    public static Map<String, Object> generatePolicy(String principalId, String effect, Object resource) {
        Map<String, Object> statement = new HashMap<>();
        statement.put("Action", "execute-api:Invoke");
        statement.put("Effect", effect);
        statement.put("Resource", resource);

        Map<String, Object> policyDocument = new HashMap<>();
        policyDocument.put("Version", "2012-10-17");
        policyDocument.put("Statement", List.of(statement));

        Map<String, Object> response = new HashMap<>();
        response.put("principalId", principalId);
        response.put("policyDocument", policyDocument);
        response.put("context", new HashMap<>());

        return response;
    }
}
