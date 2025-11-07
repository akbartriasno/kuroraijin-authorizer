package com.kuroraijin;

import com.kuroraijin.service.FindUserService;
import com.kuroraijin.service.JWTService;
import com.kuroraijin.util.PolicyDocumentUtil;
import io.micronaut.function.aws.MicronautRequestHandler;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;

@Singleton
public class CoreAuthorizerHandler extends MicronautRequestHandler<Map<String, Object>, Map<String, Object>> {

    private static final Logger LOG = LoggerFactory.getLogger(CoreAuthorizerHandler.class);

    @Inject JWTService jwtService;
    @Inject FindUserService findUserService;

    @Override
    public Map<String, Object> execute(Map<String, Object> event) {
        try {
            LOG.info("Incoming authorizer event: {}", safeStr(event));

            // Get Token
            String rawToken = extractRawAuthorization(event);
            if (rawToken == null || rawToken.isBlank()) {
                LOG.warn("No bearer token found");
                return PolicyDocumentUtil.generatePolicy("Guest-No-Token", "Deny", "*");
            }

            // Clean Token
            String compactJws = stripBearer(rawToken);
            if (compactJws.isBlank()) {
                LOG.warn("Empty compact JWS after stripping Bearer");
                return PolicyDocumentUtil.generatePolicy("Guest-Empty-Token", "Deny", "*");
            }

            // Verify and get Email
            String email = jwtService.verifyAndGetEmail(compactJws);
            if (email == null) {
                LOG.warn("JWT verification failed");
                return PolicyDocumentUtil.generatePolicy("Guest-Invalid-Token", "Deny", "*");
            }

            return findUserService.findUser(email);
        } catch (Exception e) {
            LOG.error("Authorizer error: {}", e.getMessage(), e);
            return PolicyDocumentUtil.generatePolicy("Guest-Exception", "Deny", "*");
        }
    }

    private String extractRawAuthorization(Map<String, Object> event) {
        // HTTP API / REQUEST authorizer: header Authorization/authorization
        Object headersObj = event.get("headers");
        if (headersObj instanceof Map<?, ?> headers) {
            Object auth = headers.get("Authorization");
            if (auth == null) auth = headers.get("authorization");
            if (auth instanceof String s && !s.isBlank()) {
                return s.trim();
            }
        }

        // REST API / TOKEN authorizer: authorizationToken
        Object token = event.get("authorizationToken");
        if (token instanceof String s && !s.isBlank()) {
            return s.trim();
        }
        return null;
    }

    private String stripBearer(String value) {
        String v = Optional.ofNullable(value).orElse("");
        if (v.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return v.substring(7).trim();
        }
        return v.trim();
    }

    private static String safeStr(Object o) {
        try { return String.valueOf(o); } catch (Exception e) { return "<unprintable>"; }
    }
}
