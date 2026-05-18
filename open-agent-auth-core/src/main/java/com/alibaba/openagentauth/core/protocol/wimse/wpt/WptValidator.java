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
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Validator for Workload Proof Tokens (WPT). Verifies the signature and validity of WPTs.
 */
public class WptValidator {

    private static final Logger logger = LoggerFactory.getLogger(WptValidator.class);

    /**
     * Cache from internal {@link Jwk} to its Nimbus {@link JWK} translation.
     * Avoids re-running Base64 decode + BigInteger + anonymous ECPublicKey
     * allocation on every WPT validation against the same cnf.jwk. {@code Jwk}
     * is a record, so value-based equality keys this map correctly.
     */
    private final ConcurrentHashMap<Jwk, JWK> jwkCache = new ConcurrentHashMap<>();

    public WptValidator() {
        // No verification key needed — it will be extracted from WIT's cnf.jwk
    }

    /**
     * Validates a Workload Proof Token.
     *
     * @param wpt the WorkloadProofToken to validate
     * @param wit the Workload Identity Token to verify against
     * @return a TokenValidationResult containing the validation outcome and parsed token
     */
    public TokenValidationResult<WorkloadProofToken> validate(WorkloadProofToken wpt, WorkloadIdentityToken wit) {

        // Validate arguments
        if (wpt == null) {
            logger.warn("WPT cannot be null");
            return TokenValidationResult.failure("WPT cannot be null");
        }
        if (wit == null) {
            logger.warn("WIT cannot be null");
            return TokenValidationResult.failure("WIT cannot be null");
        }
        logger.debug("Validating WPT, WIT: {}, WPT: {}", wit, wpt);

        // 1. Verify that the WPT has not expired
        String expirationError = verifyExpiration(wpt);
        if (expirationError != null) {
            logger.warn("WPT has expired: {}", expirationError);
            return TokenValidationResult.failure(expirationError);
        }

        // 2. Verify that all required claims are present in the WPT
        String requiredClaimsError = verifyRequiredClaims(wpt);
        if (requiredClaimsError != null) {
            logger.warn("WPT missing required claims: {}", requiredClaimsError);
            return TokenValidationResult.failure(requiredClaimsError);
        }

        // 3. Verify that the WPT algorithm matches the algorithm specified in WIT cnf.jwk.alg
        // This check must be done before signature verification to prevent algorithm confusion attacks
        String algorithmError = verifyAlgorithmConsistency(wpt, wit);
        if (algorithmError != null) {
            logger.warn("WPT algorithm does not match WIT cnf.jwk.alg: {}", algorithmError);
            return TokenValidationResult.failure(algorithmError);
        }

        // 4. Verify that the wth claim matches the hash of the WIT
        String wthError = verifyWth(wpt, wit);
        if (wthError != null) {
            logger.warn("WPT wth does not match WIT hash: {}", wthError);
            return TokenValidationResult.failure(wthError);
        }

        // 5. Verify the oth claim (other tokens hashes) if present
        String othError = verifyOtherTokens(wpt, wit);
        if (othError != null) {
            logger.warn("WPT oth validation failed: {}", othError);
            return TokenValidationResult.failure(othError);
        }

        // 6. Verify the signature of the WPT
        String signatureError = verifySignature(wpt, wit);
        if (signatureError != null) {
            logger.warn("WPT signature verification failed: {}", signatureError);
            return TokenValidationResult.failure(signatureError);
        }

        // All checks passed
        logger.debug("Successfully validated WPT");
        return TokenValidationResult.success(wpt);
    }

    /**
     * Verifies that the WPT has not expired.
     *
     * @param wpt the WorkloadProofToken
     * @return error message if expired, null if valid
     */
    private String verifyExpiration(WorkloadProofToken wpt) {
        if (wpt.claims() == null || wpt.claims().expirationTime() == null) {
            return "WPT missing expiration time";
        }
        if (wpt.claims().isExpired()) {
            return "WPT expired at: " + wpt.claims().expirationTime();
        }
        return null;
    }

    /**
     * Converts the internal Jwk model to a NimbusDS JWK object.
     * Caches by {@code Jwk} identity so repeated validations against the same
     * cnf.jwk skip the Base64-decode + BigInteger + anonymous-key allocation.
     */
    private JWK convertToJWK(Jwk jwk) throws JOSEException {
        if (jwk == null) {
            throw new JOSEException("Jwk cannot be null");
        }
        JWK cached = jwkCache.get(jwk);
        if (cached != null) {
            return cached;
        }
        JWK fresh = buildNimbusJwk(jwk);
        jwkCache.putIfAbsent(jwk, fresh);
        return fresh;
    }

    private JWK buildNimbusJwk(Jwk jwk) throws JOSEException {
        String keyId = jwk.keyId();
        String algorithm = jwk.algorithm();

        if (jwk.keyType() == Jwk.KeyType.EC) {
            // Convert EC key
            if (jwk.x() == null || jwk.y() == null) {
                throw new JOSEException("EC key missing required components");
            }

            Curve curve = convertToNimbusCurve(jwk.curve());
            BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.x()));
            BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.y()));
            
            ECKey.Builder builder = new ECKey.Builder(curve, new ECPublicKey() {
                @Override
                public ECPoint getW() {
                    return new ECPoint(x, y);
                }
                @Override
                public String getAlgorithm() {
                    return "EC";
                }
                @Override
                public String getFormat() {
                    return "X.509";
                }
                @Override
                public byte[] getEncoded() {
                    return null;
                }
                @Override
                public java.security.spec.ECParameterSpec getParams() {
                    return curve.toECParameterSpec();
                }
            }).keyID(keyId);
            
            if (algorithm != null) {
                JWSAlgorithm jwsAlgorithm = convertAlgorithmToJWSAlgorithm(algorithm);
                if (jwsAlgorithm != null) {
                    builder.algorithm(jwsAlgorithm);
                }
            }
            return builder.build();
        } else if (jwk.keyType() == Jwk.KeyType.RSA) {
            throw new JOSEException("RSA key conversion not yet supported");
        }

        throw new JOSEException("Unsupported key type: " + jwk.keyType());
    }

    /**
     * Converts the internal Curve enum to NimbusDS Curve.
     *
     * @param curve the internal Curve enum
     * @return the NimbusDS Curve object
     * @throws JOSEException if the curve is not supported
     */
    private Curve convertToNimbusCurve(Jwk.Curve curve) throws JOSEException {
        if (curve == null) {
            throw new JOSEException("Curve cannot be null");
        }
        return switch (curve) {
            case P_256 -> Curve.P_256;
            case P_384 -> Curve.P_384;
            case P_521 -> Curve.P_521;
            default -> throw new JOSEException("Unsupported curve: " + curve);
        };
    }

    /**
     * Converts algorithm string to JWSAlgorithm.
     *
     * @param algorithm the algorithm string
     * @return the JWSAlgorithm object, or null if not supported
     */
    private JWSAlgorithm convertAlgorithmToJWSAlgorithm(String algorithm) {
        if (algorithm == null) {
            return null;
        }
        return switch (algorithm.toUpperCase()) {
            case "RS256" -> JWSAlgorithm.RS256;
            case "RS384" -> JWSAlgorithm.RS384;
            case "RS512" -> JWSAlgorithm.RS512;
            case "ES256" -> JWSAlgorithm.ES256;
            case "ES384" -> JWSAlgorithm.ES384;
            case "ES512" -> JWSAlgorithm.ES512;
            default -> null;
        };
    }

    /**
     * Verifies the signature of the WPT.
     *
     * @param wpt the WorkloadProofToken
     * @param wit the WorkloadIdentityToken
     * @return error message if invalid, null if valid
     */
    private String verifySignature(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        try {
            // Use the JWT string for signature verification
            String wptJwtString = wpt.jwtString();
            if (ValidationUtils.isNullOrEmpty(wptJwtString)) {
                logger.warn("WPT missing JWT string, cannot verify signature");
                return "WPT missing JWT string";
            }

            // Parse the JWT string to get SignedJWT object
            SignedJWT signedJwt = SignedJWT.parse(wptJwtString);

            // Extract the public key from WIT cnf.jwk for WPT signature verification.
            // WPT must be signed with the private key corresponding to cnf.jwk.
            if (wit.getConfirmation() == null || wit.getConfirmation().jwk() == null) {
                logger.warn("WIT missing cnf.jwk, cannot verify WPT signature");
                return "WIT missing cnf.jwk";
            }

            JWK wptVerificationKey = convertToJWK(wit.getConfirmation().jwk());
            
            // Create verifier using the WIT cnf.jwk key based on key type
            JWSVerifier verifier = createVerifier(wptVerificationKey);

            // Verify the signature
            boolean isValid = signedJwt.verify(verifier);

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
            // If parsing fails, it's likely due to an invalid signature format
            // Return a signature verification error message for consistency
            return "WPT signature verification failed";
        }
    }

    /**
     * Creates a JWS verifier based on the key type.
     *
     * @param verificationKey the verification key
     * @return the JWS verifier
     * @throws JOSEException if the key type is not supported
     */
    private static JWSVerifier createVerifier(JWK verificationKey) throws JOSEException {
        if (verificationKey instanceof RSAKey) {
            return new RSASSAVerifier((RSAKey) verificationKey);
        } else if (verificationKey instanceof ECKey) {
            return new ECDSAVerifier((ECKey) verificationKey);
        } else {
            throw new JOSEException("Unsupported key type: " + verificationKey.getClass().getSimpleName());
        }
    }

    /**
     * Verifies that all required claims are present in the WPT.
     *
     * @param wpt the WorkloadProofToken
     * @return error message if missing required claims, null if valid
     */
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

    /**
     * Verifies that the wth claim matches the hash of the WIT.
     *
     * @param wpt the WorkloadProofToken
     * @param wit the Workload Identity Token
     * @return error message if not match, null if valid
     */
    private String verifyWth(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        try {
            // Use the JWT string to compute hash
            String witJwtString = wit.jwtString();
            if (ValidationUtils.isNullOrEmpty(witJwtString)) {
                logger.warn("WIT missing JWT string, cannot verify wth");
                return "WIT missing JWT string";
            }

            String expectedWth = JwtHashUtil.computeWitHash(witJwtString);
            String actualWth = wpt.claims().workloadTokenHash();

            // Verify that the wth claim matches the hash of the WIT
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

    /**
     * Verifies the oth (other tokens hashes) claim if present.
     * The oth claim contains hashes of other tokens this WPT is bound to; if it contains
     * entries not understood by the recipient, the WPT must be rejected.
     *
     * @param wpt the WorkloadProofToken
     * @param wit the Workload Identity Token (used for context)
     * @return error message if validation fails, null if valid or oth not present
     */
    private String verifyOtherTokens(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        try {
            // Check if oth claim is present
            if (wpt.claims().otherTokenHashes() == null ||
                wpt.claims().otherTokenHashes().isEmpty()) {
                // oth is optional, so it's okay if not present
                logger.debug("WPT does not contain oth claim, skipping validation");
                return null;
            }

            Map<String, String> otherTokenHashes = wpt.claims().otherTokenHashes();
            logger.debug("Validating WPT oth claim with {} token types", otherTokenHashes.size());

            // Validate each token type in oth claim
            for (Map.Entry<String, String> entry : otherTokenHashes.entrySet()) {
                String tokenType = entry.getKey();
                String expectedHash = entry.getValue();

                String validationResult = validateOtherTokenType(tokenType, expectedHash);
                if (validationResult != null) {
                    return validationResult;
                }
            }

            logger.debug("All oth claim entries validated successfully");
            return null;

        } catch (Exception e) {
            logger.error("Error validating oth claim", e);
            return "Error validating oth claim: " + e.getMessage();
        }
    }

    /**
     * Validates the format of a specific entry in the oth claim.
     *
     * @param tokenType the token type identifier
     * @param expectedHash the expected hash value
     * @return error message if validation fails, null if valid
     */
    private String validateOtherTokenType(String tokenType, String expectedHash) {

        // Validate hash format
        if (expectedHash == null || expectedHash.trim().isEmpty()) {
            return "WPT oth claim has empty hash for token type: '%s'".formatted(tokenType);
        }

        // Validate token type format
        if (tokenType == null || tokenType.trim().isEmpty()) {
            return "WPT oth claim contains empty token type key";
        }

        // Validate token type follows naming conventions (lowercase, alphanumeric, hyphens, underscores)
        if (!tokenType.matches("^[a-z0-9_-]+$")) {
            return "WPT oth claim token type '%s' has invalid format".formatted(tokenType);
        }

        logger.debug("WPT oth claim contains valid entry for token type: {}", tokenType);
        return null;
    }

    /**
     * Verifies that the WPT algorithm matches the algorithm specified in WIT cnf.jwk.alg.
     * This prevents algorithm confusion attacks.
     *
     * @param wpt the WorkloadProofToken
     * @param wit the Workload Identity Token
     * @return error message if not match, null if valid
     */
    private String verifyAlgorithmConsistency(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        try {
            // Get WPT header algorithm
            String wptAlg = wpt.header().algorithm();
            if (ValidationUtils.isNullOrEmpty(wptAlg)) {
                return "WPT missing algorithm in header";
            }

            // Get WIT cnf.jwk.alg from the structured object
            if (wit.getConfirmation() == null || wit.getConfirmation().jwk() == null) {
                return "WIT missing cnf.jwk claim";
            }

            String witAlg = wit.getConfirmation().jwk().algorithm();
            if (ValidationUtils.isNullOrEmpty(witAlg)) {
                return "WIT cnf.jwk missing alg field";
            }

            // Verify algorithm consistency
            if (!wptAlg.equals(witAlg)) {
                return "WPT algorithm '%s' does not match WIT cnf.jwk.alg '%s'".formatted(wptAlg, witAlg);
            } else {
                return null;
            }
        } catch (Exception e) {
            logger.error("Error verifying algorithm consistency", e);
            return "Error verifying algorithm consistency: " + e.getMessage();
        }
    }
}