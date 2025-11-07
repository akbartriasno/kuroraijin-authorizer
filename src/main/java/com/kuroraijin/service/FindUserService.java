package com.kuroraijin.service;

import com.kuroraijin.util.PolicyDocumentUtil;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import io.micronaut.context.annotation.Value;
import jakarta.annotation.PreDestroy;
import jakarta.inject.Singleton;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static com.mongodb.client.model.Filters.eq;

@Singleton
public class FindUserService {

    private static final Logger LOG = LoggerFactory.getLogger(FindUserService.class);

    private final String MONGO_URI;
    private final String ACCOUNT_ID;
    private final String AUTH_DATABASE;

    private static final String USERS = "users";
    private static final String ROLES = "roles";

    // Reuse MongoDB client across invocations
    private MongoClient mongoClient;

    public FindUserService(
            @Value("${mongodb.uri}") String mongoUri,
            @Value("${aws.accountid}") String accountId,
            @Value("${mongodb.auth.database}") String authDatabase) {
        MONGO_URI = mongoUri;
        ACCOUNT_ID = accountId;
        AUTH_DATABASE = authDatabase;
        if (MONGO_URI == null) {
            throw new IllegalStateException("Environment variable MONGODB_URI is not set");
        }
    }

    // Lazy initialization of MongoDB client
    private MongoClient getMongoClient() {
        if (mongoClient == null) {
            synchronized (this) {
                if (mongoClient == null) {
                    LOG.info("Initializing MongoDB client");
                    mongoClient = MongoClients.create(MONGO_URI);
                }
            }
        }
        return mongoClient;
    }

    @PreDestroy
    public void cleanup() {
        if (mongoClient != null) {
            LOG.info("Closing MongoDB client");
            mongoClient.close();
        }
    }

    public Map<String, Object> findUser(String email) {
        LOG.info("Finding user: {}", email);

        try {
            MongoClient client = getMongoClient();
            MongoDatabase db = client.getDatabase(AUTH_DATABASE);

            MongoCollection<Document> users = db.getCollection(USERS);
            MongoCollection<Document> roles = db.getCollection(ROLES);

            // Find User
            Document query = new Document("email", email);
            Document userDoc = users.find(query).first();

            if (userDoc == null) {
                LOG.warn("No user found with email {}", email);
                return PolicyDocumentUtil.generatePolicy("Guest-No-User-Found", "Deny", "");
            }

            ObjectId userId = userDoc.getObjectId("_id");
            String roleCode = userDoc.getString("role");
            if (roleCode == null || roleCode.isBlank()) {
                LOG.warn("User has no role: {}", email);
                return PolicyDocumentUtil.generatePolicy("Guest-No-Role", "Deny", "");
            }

            // Get Document by Role
            Document roleDoc = roles.find(eq("code", roleCode)).first();
            if (roleDoc == null) {
                LOG.warn("Role not found: {}", roleCode);
                return PolicyDocumentUtil.generatePolicy("Guest-Role-Not-Found", "Deny", "");
            }

            // Build document authorizer
            List<Document> accessGranted = roleDoc.getList(
                    "access_granted", Document.class, Collections.emptyList());
            Set<String> resourceArns = new LinkedHashSet<>();

            for (Document ag : accessGranted) {
                String method = optString(ag, "method", "*");
                String path = optString(ag, "path", "/*");

                Document res = ag.get("resource", Document.class);
                if (res == null) {
                    LOG.warn("Missing resource object in access_granted item: {}", ag.toJson());
                    continue;
                }

                String region = optString(res, "region", "*");
                String apiId  = optString(res, "api_id", "*");
                String stage  = optString(res, "stage", "*");

                // normalize the path so that there is a leading slash
                if (!path.startsWith("/")) {
                    path = "/" + path;
                }

                // Format ARN API Gateway:
                // arn:aws:execute-api:{region}:{account_id}:{apiId}/{stage}/{method}{path}
                String arn = String.format(
                        "arn:aws:execute-api:%s:%s:%s/%s/%s%s",
                        region, ACCOUNT_ID, apiId, stage, method, path
                );

                resourceArns.add(arn);
            }

            if (resourceArns.isEmpty()) {
                LOG.warn("No access entries built for user {}", email);
                return PolicyDocumentUtil.generatePolicy("Guest-No-Access", "Deny", "");
            }

            LOG.info("Access for {} -> {}", email, resourceArns);
            // principalId = _id user
            return PolicyDocumentUtil.generatePolicy(userId.toHexString(), "Allow", new ArrayList<>(resourceArns));
        } catch (Exception e) {
            LOG.error("findUser error: {}", e.getMessage(), e);
            return PolicyDocumentUtil.generatePolicy("Guest-FindUser-Error", "Deny", "");
        }
    }

    private static String optString(Document doc, String key, String def) {
        String v = doc.getString(key);
        return (v == null || v.isBlank()) ? def : v;
    }
}