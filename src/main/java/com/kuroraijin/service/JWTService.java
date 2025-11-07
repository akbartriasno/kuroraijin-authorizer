package com.kuroraijin.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.Value;
import io.micronaut.core.io.ResourceResolver;
import jakarta.annotation.PostConstruct;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

@Singleton
public class JWTService {

    private static final Logger LOG = LoggerFactory.getLogger(JWTService.class);

    private PublicKey publicKey;
    private final String publicKeyPath;
    private final ResourceResolver resourceResolver;
    private static final long CLOCK_SKEW_SEC = 60;

    public JWTService(@Value("${pem.public.path}") String publicKeyPath,
                      ResourceResolver resourceResolver) {
        this.publicKeyPath = publicKeyPath;
        this.resourceResolver = resourceResolver;
    }

    @PostConstruct
    void init() {
        try {
            String key = loadPemContent(publicKeyPath);
            key = key.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
            LOG.info("RSA Public Key loaded successfully");
        } catch (Exception e) {
            LOG.warn("Failed to load RSA public key: {}", e.getMessage());
        }
    }

    public String verifyAndGetEmail(String token) {
        if (token == null || token.isBlank()) {
            LOG.warn("Empty token");
            return null;
        }
        if (publicKey == null) {
            LOG.warn("Public key not initialized");
            return null;
        }
        try {
            // 1) Parse token
            SignedJWT signed = SignedJWT.parse(token);

            // 2) Pastikan algoritma RS256
            JWSHeader header = signed.getHeader();
            if (header == null || header.getAlgorithm() == null || !JWSAlgorithm.RS256.equals(header.getAlgorithm())) {
                LOG.warn("Unsupported JWS algorithm: {}", header != null ? header.getAlgorithm() : "null");
                return null;
            }

            // 3) Verifikasi signature
            RSASSAVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            if (!signed.verify(verifier)) {
                LOG.warn("JWT signature verification failed");
                return null;
            }

            // 4) Validasi klaim waktu
            JWTClaimsSet claims = signed.getJWTClaimsSet();
            Date now = new Date();

            Date exp = claims.getExpirationTime();
            if (exp == null || now.after(new Date(exp.getTime() + CLOCK_SKEW_SEC * 1000))) {
                LOG.warn("JWT expired");
                return null;
            }

            Date nbf = claims.getNotBeforeTime();
            if (nbf != null && now.before(new Date(nbf.getTime() - CLOCK_SKEW_SEC * 1000))) {
                LOG.warn("JWT not yet valid (nbf)");
                return null;
            }

            Object purpose = claims.getClaim("purpose");
            if (purpose == null || !"access".equals(purpose.toString())) {
                LOG.warn("Invalid or missing 'purpose' claim");
                return null;
            }

            String sub = claims.getSubject();
            if (sub == null || sub.isBlank()) {
                LOG.warn("Missing 'sub' claim");
                return null;
            }

            return sub;
        } catch (ParseException | JOSEException e) {
            LOG.warn("JWT parse/verify error: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            LOG.warn("JWT validation unexpected error: {}", e.getMessage());
            return null;
        }
    }

    private String loadPemContent(String path) throws IOException {
        Optional<InputStream> inputStream = resourceResolver.getResourceAsStream(path);
        if (inputStream.isEmpty()) {
            throw new IOException("Could not find resource: " + path);
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream.get()))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

}
