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
package ai.shao.aap.rs.core.protocol.dpop;

import ai.shao.aap.rs.core.crypto.JwtHashUtil;
import ai.shao.aap.rs.core.model.jwk.Jwk;
import ai.shao.aap.rs.core.model.token.CredentialToken;
import ai.shao.aap.rs.core.model.token.DpopToken;
import ai.shao.aap.rs.core.token.common.TokenValidationResult;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validator for DPoP proofs. Verifies the signature and validity of a {@link DpopToken} against the
 * binding {@link CredentialToken}. Only Ed25519 ({@code alg=EdDSA}) is supported.
 */
public class DpopValidator {

    private static final Logger logger = LoggerFactory.getLogger(DpopValidator.class);

    /**
     * Cache from internal {@link Jwk} to its Nimbus {@link JWK} translation. Avoids re-decoding the
     * {@code x} parameter on every DPoP validation against the same cnf.jwk. {@code Jwk} is a
     * record, so value-based equality keys this map correctly.
     */
    private final ConcurrentHashMap<Jwk, JWK> jwkCache = new ConcurrentHashMap<>();

    public DpopValidator() {}

    public TokenValidationResult<DpopToken> validate(DpopToken dpop, CredentialToken ct) {
        return validate(null, dpop, ct);
    }

    public TokenValidationResult<DpopToken> validate(
            @Nullable SignedJWT signedJwt, DpopToken dpop, CredentialToken ct) {

        if (dpop == null) {
            logger.warn("DPoP cannot be null");
            return TokenValidationResult.failure("DPoP cannot be null");
        }
        if (ct == null) {
            logger.warn("CT cannot be null");
            return TokenValidationResult.failure("CT cannot be null");
        }
        logger.debug("Validating DPoP, CT: {}, DPoP: {}", ct, dpop);

        Result step;

        step = verifyExpiration(dpop);
        if (step instanceof Result.Err(String msg)) {
            logger.warn("DPoP has expired: {}", msg);
            return TokenValidationResult.failure(msg);
        }

        step = verifyRequiredClaims(dpop);
        if (step instanceof Result.Err(String msg)) {
            logger.warn("DPoP missing required claims: {}", msg);
            return TokenValidationResult.failure(msg);
        }

        step = verifyWth(dpop, ct);
        if (step instanceof Result.Err(String msg)) {
            logger.warn("DPoP wth does not match CT hash: {}", msg);
            return TokenValidationResult.failure(msg);
        }

        step = verifySignature(signedJwt, dpop, ct);
        if (step instanceof Result.Err(String msg)) {
            logger.warn("DPoP signature verification failed: {}", msg);
            return TokenValidationResult.failure(msg);
        }

        logger.debug("Successfully validated DPoP");
        return TokenValidationResult.success(dpop);
    }

    /** Outcome of a single verification step. */
    private sealed interface Result {
        record Ok() implements Result {}

        record Err(String message) implements Result {}
    }

    private static final Result OK = new Result.Ok();

    private Result verifyExpiration(DpopToken dpop) {
        if (dpop.claims().isExpired()) {
            return new Result.Err("DPoP expired at: " + dpop.claims().expirationTime());
        }
        return OK;
    }

    private JWK convertToJWK(Jwk jwk) {
        JWK cached = jwkCache.get(jwk);
        if (cached != null) {
            return cached;
        }
        JWK fresh = buildNimbusJwk(jwk);
        JWK winner = jwkCache.putIfAbsent(jwk, fresh);
        return winner != null ? winner : fresh;
    }

    private JWK buildNimbusJwk(Jwk jwk) {
        OctetKeyPair.Builder builder =
                new OctetKeyPair.Builder(Curve.Ed25519, new Base64URL(jwk.x()))
                        .algorithm(JWSAlgorithm.EdDSA);
        if (jwk.keyId() != null) {
            builder.keyID(jwk.keyId());
        }
        return builder.build();
    }

    private Result verifySignature(
            @Nullable SignedJWT signedJwt, DpopToken dpop, CredentialToken ct) {
        try {
            SignedJWT jwt = signedJwt;
            if (jwt == null) {
                String dpopJwtString = dpop.jwtString();
                if (dpopJwtString == null || dpopJwtString.isEmpty()) {
                    logger.warn("DPoP missing JWT string, cannot verify signature");
                    return new Result.Err("DPoP missing JWT string");
                }
                jwt = SignedJWT.parse(dpopJwtString);
            }

            JWK dpopVerificationKey = convertToJWK(ct.getConfirmation().jwk());

            JWSVerifier verifier = new Ed25519Verifier((OctetKeyPair) dpopVerificationKey);

            boolean isValid = jwt.verify(verifier);

            if (!isValid) {
                logger.warn("DPoP signature verification failed");
                return new Result.Err("DPoP signature verification failed");
            }
            logger.debug("DPoP signature verified successfully");
            return OK;

        } catch (JOSEException e) {
            logger.error("Error verifying DPoP signature", e);
            return new Result.Err("Error verifying DPoP signature: " + e.getMessage());
        } catch (ParseException e) {
            logger.error("Error parsing DPoP JWT string during signature verification", e);
            return new Result.Err("DPoP signature verification failed");
        }
    }

    private Result verifyRequiredClaims(DpopToken dpop) {
        if (dpop.claims().workloadTokenHash().trim().isEmpty()) {
            return new Result.Err("DPoP missing required claim: wth");
        }
        return OK;
    }

    private Result verifyWth(DpopToken dpop, CredentialToken ct) {
        try {
            String ctJwtString = ct.jwtString();
            if (ctJwtString == null || ctJwtString.isEmpty()) {
                logger.warn("CT missing JWT string, cannot verify wth");
                return new Result.Err("CT missing JWT string");
            }

            String expectedWth = JwtHashUtil.computeWitHash(ctJwtString);
            String actualWth = dpop.claims().workloadTokenHash();

            if (!expectedWth.equals(actualWth)) {
                return new Result.Err(
                        "DPoP wth '%s' does not match CT hash '%s'"
                                .formatted(actualWth, expectedWth));
            }
            return OK;
        } catch (Exception e) {
            logger.error("Error calculating CT hash", e);
            return new Result.Err("Error calculating CT hash: " + e.getMessage());
        }
    }
}
