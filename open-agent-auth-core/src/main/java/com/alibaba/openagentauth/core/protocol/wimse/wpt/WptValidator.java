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
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Validator for Workload Proof Tokens (WPT). Verifies the signature and validity of WPTs.
 * Only Ed25519 ({@code alg=EdDSA}) is supported.
 */
public class WptValidator {

    private static final Logger logger = LoggerFactory.getLogger(WptValidator.class);

    /**
     * Cache from internal {@link Jwk} to its Nimbus {@link JWK} translation. Avoids
     * re-decoding the {@code x} parameter on every WPT validation against the same
     * cnf.jwk. {@code Jwk} is a record, so value-based equality keys this map correctly.
     */
    private final ConcurrentHashMap<Jwk, JWK> jwkCache = new ConcurrentHashMap<>();

    public WptValidator() {
    }

    public TokenValidationResult<WorkloadProofToken> validate(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        return validate(null, wpt, wit);
    }

    public TokenValidationResult<WorkloadProofToken> validate(
            SignedJWT signedJwt, WorkloadProofToken wpt, WorkloadIdentityToken wit) {

        if (wpt == null) {
            logger.warn("WPT cannot be null");
            return TokenValidationResult.failure("WPT cannot be null");
        }
        if (wit == null) {
            logger.warn("WIT cannot be null");
            return TokenValidationResult.failure("WIT cannot be null");
        }
        logger.debug("Validating WPT, WIT: {}, WPT: {}", wit, wpt);

        String expirationError = verifyExpiration(wpt);
        if (expirationError != null) {
            logger.warn("WPT has expired: {}", expirationError);
            return TokenValidationResult.failure(expirationError);
        }

        String requiredClaimsError = verifyRequiredClaims(wpt);
        if (requiredClaimsError != null) {
            logger.warn("WPT missing required claims: {}", requiredClaimsError);
            return TokenValidationResult.failure(requiredClaimsError);
        }

        String wthError = verifyWth(wpt, wit);
        if (wthError != null) {
            logger.warn("WPT wth does not match WIT hash: {}", wthError);
            return TokenValidationResult.failure(wthError);
        }

        String signatureError = verifySignature(signedJwt, wpt, wit);
        if (signatureError != null) {
            logger.warn("WPT signature verification failed: {}", signatureError);
            return TokenValidationResult.failure(signatureError);
        }

        logger.debug("Successfully validated WPT");
        return TokenValidationResult.success(wpt);
    }

    private String verifyExpiration(WorkloadProofToken wpt) {
        if (wpt.claims() == null || wpt.claims().expirationTime() == null) {
            return "WPT missing expiration time";
        }
        if (wpt.claims().isExpired()) {
            return "WPT expired at: " + wpt.claims().expirationTime();
        }
        return null;
    }

    private JWK convertToJWK(Jwk jwk) {
        JWK cached = jwkCache.get(jwk);
        if (cached != null) {
            return cached;
        }
        JWK fresh = buildNimbusJwk(jwk);
        jwkCache.putIfAbsent(jwk, fresh);
        return fresh;
    }

    private JWK buildNimbusJwk(Jwk jwk) {
        OctetKeyPair.Builder builder = new OctetKeyPair.Builder(Curve.Ed25519, new Base64URL(jwk.x()))
                .algorithm(JWSAlgorithm.EdDSA);
        if (jwk.keyId() != null) {
            builder.keyID(jwk.keyId());
        }
        return builder.build();
    }

    private String verifySignature(SignedJWT signedJwt, WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        try {
            SignedJWT jwt = signedJwt;
            if (jwt == null) {
                String wptJwtString = wpt.jwtString();
                if (ValidationUtils.isNullOrEmpty(wptJwtString)) {
                    logger.warn("WPT missing JWT string, cannot verify signature");
                    return "WPT missing JWT string";
                }
                jwt = SignedJWT.parse(wptJwtString);
            }

            if (wit.getConfirmation() == null || wit.getConfirmation().jwk() == null) {
                logger.warn("WIT missing cnf.jwk, cannot verify WPT signature");
                return "WIT missing cnf.jwk";
            }

            JWK wptVerificationKey = convertToJWK(wit.getConfirmation().jwk());

            JWSVerifier verifier = new Ed25519Verifier((OctetKeyPair) wptVerificationKey);

            boolean isValid = jwt.verify(verifier);

            if (!isValid) {
                logger.warn("WPT signature verification failed");
                return "WPT signature verification failed";
            } else {
                logger.debug("WPT signature verified successfully");
                return null;
            }

        } catch (JOSEException e) {
            logger.error("Error verifying WPT signature", e);
            return "Error verifying WPT signature: " + e.getMessage();
        } catch (ParseException e) {
            logger.error("Error parsing WPT JWT string during signature verification", e);
            return "WPT signature verification failed";
        }
    }

    private String verifyRequiredClaims(WorkloadProofToken wpt) {
        if (wpt.claims() == null) {
            return "WPT missing claims";
        }
        if (wpt.claims().workloadTokenHash() == null ||
            wpt.claims().workloadTokenHash().trim().isEmpty()) {
            return "WPT missing required claim: wth";
        } else {
            return null;
        }
    }

    private String verifyWth(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        try {
            String witJwtString = wit.jwtString();
            if (ValidationUtils.isNullOrEmpty(witJwtString)) {
                logger.warn("WIT missing JWT string, cannot verify wth");
                return "WIT missing JWT string";
            }

            String expectedWth = JwtHashUtil.computeWitHash(witJwtString);
            String actualWth = wpt.claims().workloadTokenHash();

            if (ValidationUtils.isNullOrEmpty(actualWth)) {
                return "WPT missing wth claim";
            }

            if (!expectedWth.equals(actualWth)) {
                return "WPT wth '%s' does not match WIT hash '%s'".formatted(actualWth, expectedWth);
            } else {
                return null;
            }
        } catch (Exception e) {
            logger.error("Error calculating WIT hash", e);
            return "Error calculating WIT hash: " + e.getMessage();
        }
    }
}
