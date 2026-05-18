/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.openagentauth.core.protocol.wimse.wpt;

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.token.common.JwtHashUtil;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Generator for Workload Proof Tokens (WPT). Creates JWT-based proof tokens that
 * prove request authenticity.
 */
public class WptGenerator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(WptGenerator.class);

    /**
     * The media type of WPTs.
     */
    private static final String MEDIA_TYPE = "wpt+jwt";

    /**
     * Creates a new WPT generator.
     * The WPT must be signed with the private key corresponding to the public key
     * in the WIT's cnf.jwk claim.
     */
    public WptGenerator() {
        // No signing key needed - it will be extracted from WIT's cnf.jwk
    }

    /**
     * Generates a Workload Proof Token for an HTTP request.
     *
     * @param wit the Workload Identity Token
     * @param wptPrivateKey the private key corresponding to WIT's cnf.jwk for signing WPT
     * @param expirationSeconds the WPT expiration time in seconds from now
     * @return a WorkloadProofToken object
     * @throws JOSEException if token generation fails
     */
    public WorkloadProofToken generateWpt(
            WorkloadIdentityToken wit,
            JWK wptPrivateKey,
            long expirationSeconds
    ) throws JOSEException {

        ValidationUtils.validateNotNull(wit, "WIT");
        ValidationUtils.validateNotNull(wptPrivateKey, "WPT private key");
        if (expirationSeconds <= 0) {
            throw new IllegalArgumentException("Expiration seconds must be positive");
        }

        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(expirationSeconds);

        String witJwtString = wit.jwtString();
        if (ValidationUtils.isNullOrEmpty(witJwtString)) {
            throw new JOSEException("WIT missing JWT string, cannot compute wth");
        }
        String wth = JwtHashUtil.computeWitHash(witJwtString);

        String algorithm = extractAlgorithmFromWit(wit);

        WorkloadProofToken wpt = buildWptObject(wth, expiration, algorithm);
        wpt = signAndSerializeWpt(wpt, wptPrivateKey);

        logger.debug("Successfully generated and signed WPT: {}", wpt.jwtString());
        return wpt;
    }

    /**
     * Generates a Workload Proof Token and returns it as a JWT string.
     */
    public String generateWptAsString(WorkloadIdentityToken wit, JWK wptPrivateKey, long expirationSeconds) throws JOSEException {
        return generateWpt(wit, wptPrivateKey, expirationSeconds).jwtString();
    }

    /**
     * Extracts the algorithm from WIT's cnf.jwk.alg.
     * The WPT header alg parameter must match the alg value of the jwk in the cnf
     * claim of the WIT.
     *
     * @param wit the WorkloadIdentityToken
     * @return the algorithm name
     * @throws JOSEException if algorithm cannot be extracted
     */
    private String extractAlgorithmFromWit(WorkloadIdentityToken wit) throws JOSEException {

        // Check if WIT has cnf.jwk
        if (wit == null || wit.getConfirmation() == null || wit.getConfirmation().jwk() == null) {
            throw new JOSEException("WIT missing cnf.jwk claim");
        }

        // Extract algorithm from WIT's cnf.jwk.alg
        Jwk jwk = wit.getConfirmation().jwk();
        String algorithm = jwk.algorithm();

        // Check if algorithm is present
        if (ValidationUtils.isNullOrEmpty(algorithm)) {
            throw new JOSEException("WIT cnf.jwk missing alg field");
        }
        return algorithm;
    }

    private WorkloadProofToken buildWptObject(String wth, Instant expiration, String algorithm) {
        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .workloadTokenHash(wth)
                .expirationTime(Date.from(expiration))
                .jwtId(UUID.randomUUID().toString())
                .build();

        return WorkloadProofToken.builder()
                .header(WorkloadProofToken.Header.builder()
                        .type(MEDIA_TYPE)
                        .algorithm(algorithm)
                        .build())
                .claims(claims)
                .build();
    }

    /**
     * Signs and serializes the WPT, returning a new WorkloadProofToken object with the signature.
     * <p>
     * This method uses the Serializer to serialize and sign the WPT directly,
     * following the natural JWT flow of "build → sign → serialize".
     * This approach eliminates the need for manual string concatenation and
     * intermediate serialization/parsing.
     * </p>
     *
     * @param wpt the WorkloadProofToken object to sign and serialize
     * @param signingKey the private key for signing WPT (must correspond to WIT's cnf.jwk)
     * @return a new WorkloadProofToken object with the signature and JWT string populated
     * @throws JOSEException if signing or serialization fails
     */
    private WorkloadProofToken signAndSerializeWpt(WorkloadProofToken wpt, JWK signingKey) throws JOSEException {
        try {
            // Create signer based on key type
            JWSSigner signer = createSigner(signingKey);

            // Use Serializer to serialize and sign the WPT
            String signedJwtString = WptSerializer.serialize(wpt, signer);

            // Extract signature from the signed JWT string
            String[] parts = signedJwtString.split("\\.");
            String signature = parts.length > 2 ? parts[2] : "";

            // Return new WPT object with signature and JWT string populated
            return WorkloadProofToken.builder()
                    .header(wpt.header())
                    .claims(wpt.claims())
                    .signature(signature)
                    .jwtString(signedJwtString)
                    .build();

        } catch (Exception e) {
            logger.error("Failed to sign WPT", e);
            throw new JOSEException("Failed to sign WPT", e);
        }
    }

    /**
     * Creates a JWSSigner based on the key type.
     *
     * @param signingKey the JWK key
     * @return the appropriate signer
     * @throws JOSEException if the key type is not supported
     */
    private JWSSigner createSigner(JWK signingKey) throws JOSEException {
        if (signingKey instanceof RSAKey) {
            return new RSASSASigner((RSAKey) signingKey);
        } else if (signingKey instanceof ECKey) {
            return new ECDSASigner((ECKey) signingKey);
        } else {
            throw new JOSEException("Unsupported key type: " + signingKey.getClass().getSimpleName());
        }
    }

}