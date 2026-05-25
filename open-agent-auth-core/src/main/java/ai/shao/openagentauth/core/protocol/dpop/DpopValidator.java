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
package ai.shao.openagentauth.core.protocol.dpop;

import ai.shao.openagentauth.core.model.jwk.Jwk;
import ai.shao.openagentauth.core.model.token.CredentialToken;
import ai.shao.openagentauth.core.model.token.DpopToken;
import ai.shao.openagentauth.core.crypto.JwtHashUtil;
import ai.shao.openagentauth.core.token.common.TokenValidationResult;
import ai.shao.openagentauth.core.util.ValidationUtils;
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
 * Validator for DPoP Proofs (DPoP). Verifies the signature and validity of WPTs.
 * Only Ed25519 ({@code alg=EdDSA}) is supported.
 */
public class DpopValidator {

    private static final Logger logger = LoggerFactory.getLogger(DpopValidator.class);

    /**
     * Cache from internal {@link Jwk} to its Nimbus {@link JWK} translation. Avoids
     * re-decoding the {@code x} parameter on every DPoP validation against the same
     * cnf.jwk. {@code Jwk} is a record, so value-based equality keys this map correctly.
     */
    private final ConcurrentHashMap<Jwk, JWK> jwkCache = new ConcurrentHashMap<>();

    public DpopValidator() {
    }

    public TokenValidationResult<DpopToken> validate(DpopToken dpop, CredentialToken ct) {
        return validate(null, dpop, ct);
    }

    public TokenValidationResult<DpopToken> validate(
            SignedJWT signedJwt, DpopToken dpop, CredentialToken ct) {

        if (dpop == null) {
            logger.warn("DPoP cannot be null");
            return TokenValidationResult.failure("DPoP cannot be null");
        }
        if (ct == null) {
            logger.warn("CT cannot be null");
            return TokenValidationResult.failure("CT cannot be null");
        }
        logger.debug("Validating DPoP, CT: {}, DPoP: {}", ct, dpop);

        String expirationError = verifyExpiration(dpop);
        if (expirationError != null) {
            logger.warn("DPoP has expired: {}", expirationError);
            return TokenValidationResult.failure(expirationError);
        }

        String requiredClaimsError = verifyRequiredClaims(dpop);
        if (requiredClaimsError != null) {
            logger.warn("DPoP missing required claims: {}", requiredClaimsError);
            return TokenValidationResult.failure(requiredClaimsError);
        }

        String wthError = verifyWth(dpop, ct);
        if (wthError != null) {
            logger.warn("DPoP wth does not match CT hash: {}", wthError);
            return TokenValidationResult.failure(wthError);
        }

        String signatureError = verifySignature(signedJwt, dpop, ct);
        if (signatureError != null) {
            logger.warn("DPoP signature verification failed: {}", signatureError);
            return TokenValidationResult.failure(signatureError);
        }

        logger.debug("Successfully validated DPoP");
        return TokenValidationResult.success(dpop);
    }

    private String verifyExpiration(DpopToken dpop) {
        if (dpop.claims() == null || dpop.claims().expirationTime() == null) {
            return "DPoP missing expiration time";
        }
        if (dpop.claims().isExpired()) {
            return "DPoP expired at: " + dpop.claims().expirationTime();
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

    private String verifySignature(SignedJWT signedJwt, DpopToken dpop, CredentialToken ct) {
        try {
            SignedJWT jwt = signedJwt;
            if (jwt == null) {
                String dpopJwtString = dpop.jwtString();
                if (ValidationUtils.isNullOrEmpty(dpopJwtString)) {
                    logger.warn("DPoP missing JWT string, cannot verify signature");
                    return "DPoP missing JWT string";
                }
                jwt = SignedJWT.parse(dpopJwtString);
            }

            if (ct.getConfirmation() == null || ct.getConfirmation().jwk() == null) {
                logger.warn("CT missing cnf.jwk, cannot verify DPoP signature");
                return "CT missing cnf.jwk";
            }

            JWK dpopVerificationKey = convertToJWK(ct.getConfirmation().jwk());

            JWSVerifier verifier = new Ed25519Verifier((OctetKeyPair) dpopVerificationKey);

            boolean isValid = jwt.verify(verifier);

            if (!isValid) {
                logger.warn("DPoP signature verification failed");
                return "DPoP signature verification failed";
            } else {
                logger.debug("DPoP signature verified successfully");
                return null;
            }

        } catch (JOSEException e) {
            logger.error("Error verifying DPoP signature", e);
            return "Error verifying DPoP signature: " + e.getMessage();
        } catch (ParseException e) {
            logger.error("Error parsing DPoP JWT string during signature verification", e);
            return "DPoP signature verification failed";
        }
    }

    private String verifyRequiredClaims(DpopToken dpop) {
        if (dpop.claims() == null) {
            return "DPoP missing claims";
        }
        if (dpop.claims().workloadTokenHash() == null ||
            dpop.claims().workloadTokenHash().trim().isEmpty()) {
            return "DPoP missing required claim: wth";
        } else {
            return null;
        }
    }

    private String verifyWth(DpopToken dpop, CredentialToken ct) {
        try {
            String ctJwtString = ct.jwtString();
            if (ValidationUtils.isNullOrEmpty(ctJwtString)) {
                logger.warn("CT missing JWT string, cannot verify wth");
                return "CT missing JWT string";
            }

            String expectedWth = JwtHashUtil.computeWitHash(ctJwtString);
            String actualWth = dpop.claims().workloadTokenHash();

            if (ValidationUtils.isNullOrEmpty(actualWth)) {
                return "DPoP missing wth claim";
            }

            if (!expectedWth.equals(actualWth)) {
                return "DPoP wth '%s' does not match CT hash '%s'".formatted(actualWth, expectedWth);
            } else {
                return null;
            }
        } catch (Exception e) {
            logger.error("Error calculating CT hash", e);
            return "Error calculating CT hash: " + e.getMessage();
        }
    }
}
