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
package ai.shao.aap.rs.core.protocol.ct;

import ai.shao.aap.rs.core.crypto.key.KeyManager;
import ai.shao.aap.rs.core.crypto.verify.SignatureVerificationUtils;
import ai.shao.aap.rs.core.model.token.CredentialToken;
import ai.shao.aap.rs.core.token.common.TokenValidationResult;
import ai.shao.aap.rs.core.trust.TrustDomain;
import ai.shao.aap.rs.core.util.ValidationUtils;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validator for Credential Tokens (CT). Verifies the signature, expiration, and structure of a
 * {@link CredentialToken}.
 */
public class CtValidator {

    /** Logger for this class. */
    private static final Logger logger = LoggerFactory.getLogger(CtValidator.class);

    /** The expected trust domain for validation. */
    private final TrustDomain expectedTrustDomain;

    /**
     * The key manager used for verifying CT signatures. Supports dynamic key rotation through
     * KeyManager abstraction.
     */
    private final KeyManager keyManager;

    /** The key ID used for signature verification. */
    private final String verificationKeyId;

    /** The CT parser. */
    private final CtParser ctParser;

    /**
     * Creates a new CT validator with a key manager, verification key ID, and trust domain.
     *
     * <p>This constructor supports dynamic key rotation through the KeyManager abstraction.
     *
     * @param keyManager the key manager for signature verification
     * @param verificationKeyId the key ID used for signature verification
     * @param expectedTrustDomain the expected trust domain for validation
     * @throws IllegalArgumentException if keyManager or expectedTrustDomain is null, or
     *     verificationKeyId is empty
     */
    public CtValidator(
            KeyManager keyManager, String verificationKeyId, TrustDomain expectedTrustDomain) {
        this.keyManager = ValidationUtils.validateNotNull(keyManager, "Key manager");
        this.verificationKeyId =
                ValidationUtils.validateNotEmpty(verificationKeyId, "Verification key ID");
        this.expectedTrustDomain =
                ValidationUtils.validateNotNull(expectedTrustDomain, "Expected trust domain");
        this.ctParser = new CtParser();

        logger.info(
                "CtValidator initialized with KeyManager: {}, keyId: {}, domain: {}",
                keyManager.getClass().getSimpleName(),
                verificationKeyId,
                expectedTrustDomain.domainId());
    }

    /**
     * Validates a Credential Token.
     *
     * @param ctJwt the JWT string representing the CT
     * @return a TokenValidationResult containing the validation outcome and parsed token
     * @throws ParseException if the JWT cannot be parsed
     */
    public TokenValidationResult<CredentialToken> validate(String ctJwt) throws ParseException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(ctJwt)) {
            return TokenValidationResult.failure("CT cannot be null or empty");
        }

        SignedJWT signedJwt = SignedJWT.parse(ctJwt);

        // 1. Verify the signature of the CT
        if (!verifySignature(signedJwt)) {
            return TokenValidationResult.failure("Invalid CT signature");
        }

        // 2. Verify that the CT has not expired
        if (!verifyExpiration(signedJwt)) {
            return TokenValidationResult.failure("CT has expired");
        }

        // 3. Verify that the CT issuer matches the expected trust domain
        if (!verifyTrustDomain(signedJwt)) {
            return TokenValidationResult.failure("Invalid trust domain");
        }

        // 4. Verify that all required claims are present in the CT
        if (!verifyRequiredClaims(signedJwt)) {
            return TokenValidationResult.failure("Missing required claims");
        }

        // 5. Verify that the cnf claim contains a valid JWK
        // cnf is REQUIRED in this implementation, so missing cnf is a required claims error
        CnfValidationResult cnfResult = verifyCnfClaim(signedJwt);
        if (!cnfResult.valid()) {
            if (cnfResult.missing()) {
                return TokenValidationResult.failure("Missing required claims");
            } else {
                return TokenValidationResult.failure("Invalid cnf claim");
            }
        }

        // Parse the CT and return the parsed token
        CredentialToken ct = ctParser.parse(signedJwt);
        logger.debug("Successfully validated CT with subject: {}", ct.getSubject());

        return TokenValidationResult.success(ct);
    }

    /**
     * Verifies the signature of the CT.
     *
     * @param signedJwt the signed JWT
     * @return true if the signature is valid, false otherwise
     */
    private boolean verifySignature(SignedJWT signedJwt) {
        return SignatureVerificationUtils.verifySignature(signedJwt, keyManager, verificationKeyId);
    }

    /**
     * Verifies that the CT has not expired.
     *
     * @param signedJwt the signed JWT
     * @return true if the token is not expired, false otherwise
     */
    @SuppressWarnings("JavaUtilDate") // Nimbus JWTClaimsSet#getExpirationTime returns Date; we
    //                                   convert to Instant immediately for the comparison.
    private boolean verifyExpiration(SignedJWT signedJwt) {
        try {
            Date rawExp = signedJwt.getJWTClaimsSet().getExpirationTime();
            if (rawExp == null) {
                logger.warn("CT missing expiration time");
                return false;
            }
            Instant expirationTime = rawExp.toInstant();

            boolean isValid = Instant.now().isBefore(expirationTime);
            if (!isValid) {
                logger.warn("CT has expired at: {}", expirationTime);
            }
            return isValid;

        } catch (ParseException e) {
            logger.error("Error parsing CT expiration time", e);
            return false;
        }
    }

    /**
     * Verifies that the CT issuer matches the expected trust domain.
     *
     * @param signedJwt the signed JWT
     * @return true if the trust domain is valid, false otherwise
     */
    private boolean verifyTrustDomain(SignedJWT signedJwt) {
        try {
            // Get CT issuer
            String issuer = signedJwt.getJWTClaimsSet().getIssuer();
            boolean isValid = expectedTrustDomain.domainId().equals(issuer);

            // Log if trust domain is invalid
            if (!isValid) {
                logger.warn(
                        "CT issuer '{}' does not match expected trust domain '{}'",
                        issuer,
                        expectedTrustDomain.domainId());
            }
            return isValid;

        } catch (ParseException e) {
            logger.error("Error parsing CT issuer", e);
            return false;
        }
    }

    /**
     * Verifies that required claims are present in the CT: {@code sub}, {@code exp}, and {@code
     * cnf}.
     *
     * @param signedJwt the signed JWT
     * @return true if all required claims are present, false otherwise
     */
    private boolean verifyRequiredClaims(SignedJWT signedJwt) {
        try {
            // Get CT claims
            var claims = signedJwt.getJWTClaimsSet().getClaims();

            // Verify subject (sub) claim - REQUIRED
            if (!claims.containsKey("sub")) {
                logger.warn("CT missing required claim: sub (subject)");
                return false;
            }

            // Verify expiration (exp) claim - REQUIRED
            if (!claims.containsKey("exp")) {
                logger.warn("CT missing required claim: exp (expiration time)");
                return false;
            }

            // cnf (confirmation) claim is REQUIRED for proof-of-possession verification.
            if (!claims.containsKey("cnf")) {
                logger.warn("CT missing required claim: cnf (confirmation)");
                return false;
            }

            return true;

        } catch (ParseException e) {
            logger.error("Error parsing CT claims", e);
            return false;
        }
    }

    /**
     * Verifies the cnf claim contains a valid JWK.
     *
     * @param signedJwt the signed JWT
     * @return a CnfValidationResult indicating whether the cnf claim is valid, missing, or invalid
     */
    private CnfValidationResult verifyCnfClaim(SignedJWT signedJwt) {
        try {
            // Get CT cnf claim
            Map<String, Object> cnfClaim = signedJwt.getJWTClaimsSet().getJSONObjectClaim("cnf");

            // cnf claim is REQUIRED in this implementation
            if (cnfClaim == null) {
                logger.warn("CT cnf claim is not present (required)");
                return new CnfValidationResult(false, true);
            }

            // Verify it contains a valid jwk
            if (!cnfClaim.containsKey("jwk")) {
                logger.warn("CT cnf claim missing jwk");
                return new CnfValidationResult(false, false);
            }

            // Validate that the jwk is a valid JWK with safe type conversion
            Object jwkObj = cnfClaim.get("jwk");
            if (!(jwkObj instanceof Map)) {
                logger.warn("CT cnf.jwk is not a Map");
                return new CnfValidationResult(false, false);
            }

            // Validate that the jwk is a valid JWK
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) jwkObj;
            try {
                JWK.parse(jwkMap);
                logger.debug("CT cnf.jwk is valid");
                return new CnfValidationResult(true, false);
            } catch (ParseException e) {
                logger.warn("CT cnf.jwk is invalid: {}", e.getMessage());
                return new CnfValidationResult(false, false);
            }
        } catch (ParseException e) {
            logger.error("Error parsing CT cnf claim", e);
            return new CnfValidationResult(false, false);
        }
    }

    /** Result of cnf claim validation. */
    private record CnfValidationResult(boolean valid, boolean missing) {}
}
