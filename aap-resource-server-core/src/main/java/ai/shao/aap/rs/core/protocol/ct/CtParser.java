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

import ai.shao.aap.rs.core.crypto.JwkConverter;
import ai.shao.aap.rs.core.model.jwk.Jwk;
import ai.shao.aap.rs.core.model.token.CredentialToken;
import ai.shao.aap.rs.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parser for Credential Tokens (CT). Converts signed JWT strings into structured {@link
 * CredentialToken} objects.
 */
public class CtParser {

    private static final String EXPECTED_TYP = "ct+jwt";

    /** Per AAP spec §3: only {alg, typ} JOSE header params allowed on CT. */
    private static final Set<String> ALLOWED_HEADER_PARAMS = Set.of("alg", "typ");

    private static final Logger logger = LoggerFactory.getLogger(CtParser.class);

    /**
     * Parses a CT from a signed JWT.
     *
     * <p>This method extracts all claims from the JWT and constructs a structured {@link
     * CredentialToken} object. It validates the input and provides detailed error messages if
     * parsing fails.
     *
     * @param signedJwt the signed JWT to parse
     * @return a CredentialToken object
     * @throws ParseException if parsing fails due to invalid JWT structure or claims
     * @throws IllegalArgumentException if signedJwt is null
     */
    public CredentialToken parse(SignedJWT signedJwt) throws ParseException {

        ValidationUtils.validateNotNull(signedJwt, "Signed JWT");

        logger.debug("Parsing Credential Token");

        JWSAlgorithm alg = signedJwt.getHeader().getAlgorithm();
        if (!JWSAlgorithm.EdDSA.equals(alg)) {
            throw new ParseException("CT alg header must be 'EdDSA', got: " + alg, 0);
        }

        JOSEObjectType typ = signedJwt.getHeader().getType();
        if (typ == null || !EXPECTED_TYP.equals(typ.getType())) {
            throw new ParseException(
                    "CT typ header must be '" + EXPECTED_TYP + "', got: " + typ, 0);
        }

        Set<String> headerParams = signedJwt.getHeader().toJSONObject().keySet();
        for (String name : headerParams) {
            if (!ALLOWED_HEADER_PARAMS.contains(name)) {
                throw new ParseException(
                        "CT JOSE header contains disallowed parameter: " + name, 0);
            }
        }

        var claims = signedJwt.getJWTClaimsSet();

        CredentialToken.Claims.Confirmation confirmation = parseConfirmationClaim(claims);

        CredentialToken ct = buildCredentialToken(signedJwt, claims, confirmation);

        logger.debug("Successfully parsed CT with subject: {}", ct.getSubject());
        return ct;
    }

    /**
     * Parses the confirmation (cnf) claim from the JWT claims set. Contains the public key (JWK)
     * used to verify DPoP Proofs. Per AAP spec the cnf claim is REQUIRED on every CT — missing cnf
     * surfaces as a ParseException.
     */
    private CredentialToken.Claims.Confirmation parseConfirmationClaim(JWTClaimsSet claims)
            throws ParseException {

        Map<String, Object> cnfClaim = claims.getJSONObjectClaim("cnf");

        if (cnfClaim == null) {
            throw new ParseException("CT missing required claim: cnf", 0);
        }

        // Validate cnf.jwk
        if (!cnfClaim.containsKey("jwk")) {
            throw new ParseException("cnf claim missing required 'jwk' field", 0);
        }

        try {
            // Extract JWK map
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) cnfClaim.get("jwk");

            // Validate JWK structure
            JWK.parse(jwkMap);

            // Convert to our Jwk model
            Jwk jwkModel = JwkConverter.convertMapToJwk(jwkMap);

            // Build confirmation object
            return CredentialToken.Claims.Confirmation.builder().jwk(jwkModel).build();

        } catch (Exception e) {
            throw new ParseException("Failed to parse cnf.jwk claim: " + e.getMessage(), 0);
        }
    }

    /**
     * Builds a structured CredentialToken object from parsed components.
     *
     * @param signedJwt the signed JWT
     * @param claims the JWT claims set
     * @param confirmation the parsed confirmation claim
     * @return a CredentialToken object
     */
    @SuppressWarnings("JavaUtilDate") // Nimbus JWTClaimsSet#getExpirationTime returns Date; we
    //                                   convert to Instant immediately when building Claims.
    private CredentialToken buildCredentialToken(
            SignedJWT signedJwt,
            JWTClaimsSet claims,
            CredentialToken.Claims.Confirmation confirmation) {

        // Build claims
        Date rawExp = claims.getExpirationTime();
        CredentialToken.Claims.ClaimsBuilder claimsBuilder =
                CredentialToken.Claims.builder()
                        .issuer(claims.getIssuer())
                        .subject(claims.getSubject())
                        .expirationTime(rawExp == null ? null : rawExp.toInstant())
                        .jwtId(claims.getJWTID())
                        .confirmation(confirmation);

        // Serialize the JWT to preserve the original JWT string. The JWT
        // was just parsed successfully, so serialize() should never fail
        // here — propagate as IllegalStateException if it somehow does.
        String jwtString;
        try {
            jwtString = signedJwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize CT JWT", e);
        }

        return CredentialToken.builder().claims(claimsBuilder.build()).jwtString(jwtString).build();
    }
}
