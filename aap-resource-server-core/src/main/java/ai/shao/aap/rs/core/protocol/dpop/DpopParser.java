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

import ai.shao.aap.rs.core.model.token.DpopToken;
import ai.shao.aap.rs.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.Date;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parser for DPoP Proofs (DPoP). Converts signed JWT strings into structured {@link DpopToken}
 * objects.
 */
public class DpopParser {

    private static final String EXPECTED_TYP = "dpop+jwt";

    /** Per AAP spec §3: DPoP allows {alg, typ, jwk} JOSE header params. */
    private static final Set<String> ALLOWED_HEADER_PARAMS = Set.of("alg", "typ", "jwk");

    private static final Logger logger = LoggerFactory.getLogger(DpopParser.class);

    /**
     * Parses a DPoP from a signed JWT.
     *
     * <p>This method extracts all claims from the JWT and constructs a structured {@link DpopToken}
     * object. It validates the input and provides detailed error messages if parsing fails.
     *
     * @param signedJwt the signed JWT to parse
     * @return a DpopToken object
     * @throws ParseException if parsing fails due to invalid JWT structure or claims
     * @throws IllegalArgumentException if signedJwt is null
     */
    public DpopToken parse(SignedJWT signedJwt) throws ParseException {

        ValidationUtils.validateNotNull(signedJwt, "Signed JWT");

        logger.debug("Parsing DPoP Proof");

        JWTClaimsSet claimsSet = signedJwt.getJWTClaimsSet();

        DpopToken dpop = buildDpopToken(signedJwt, claimsSet, signedJwt.serialize());

        logger.debug("Successfully parsed DPoP with JWT ID: {}", dpop.getJwtId());
        return dpop;
    }

    /**
     * Builds a structured DpopToken object from parsed components.
     *
     * @param signedJwt the signed JWT
     * @param claimsSet the JWT claims set
     * @param jwtString the original JWT string
     * @return a DpopToken object
     * @throws ParseException if claims parsing fails
     */
    private DpopToken buildDpopToken(SignedJWT signedJwt, JWTClaimsSet claimsSet, String jwtString)
            throws ParseException {

        JWSAlgorithm alg = signedJwt.getHeader().getAlgorithm();
        if (!JWSAlgorithm.EdDSA.equals(alg)) {
            throw new ParseException("DPoP alg header must be 'EdDSA', got: " + alg, 0);
        }

        JOSEObjectType typ = signedJwt.getHeader().getType();
        if (typ == null || !EXPECTED_TYP.equals(typ.getType())) {
            throw new ParseException(
                    "DPoP typ header must be '" + EXPECTED_TYP + "', got: " + typ, 0);
        }

        Set<String> headerParams = signedJwt.getHeader().toJSONObject().keySet();
        for (String name : headerParams) {
            if (!ALLOWED_HEADER_PARAMS.contains(name)) {
                throw new ParseException(
                        "DPoP JOSE header contains disallowed parameter: " + name, 0);
            }
        }

        // Build claims. Nimbus's getExpirationTime() returns Date — convert to Instant.
        @SuppressWarnings("JavaUtilDate")
        Date rawExp = claimsSet.getExpirationTime();
        DpopToken.Claims claims =
                DpopToken.Claims.builder()
                        .audience(getStringClaim(claimsSet, "aud"))
                        .expirationTime(rawExp == null ? null : rawExp.toInstant())
                        .jwtId(claimsSet.getJWTID())
                        .workloadTokenHash(getStringClaim(claimsSet, "wth"))
                        .accessTokenHash(getStringClaim(claimsSet, "ath"))
                        .build();

        // Build DPoP
        return DpopToken.builder()
                .claims(claims)
                .signature(signedJwt.getSignature().toString())
                .jwtString(jwtString)
                .build();
    }

    /**
     * Gets a string claim from the claims set.
     *
     * @param claimsSet the JWT claims set
     * @param claimName the claim name
     * @return the claim value, or null if not present
     */
    private @Nullable String getStringClaim(JWTClaimsSet claimsSet, String claimName)
            throws ParseException {
        Object value = claimsSet.getClaim(claimName);
        if (value == null) {
            return null;
        }
        return value.toString();
    }
}
