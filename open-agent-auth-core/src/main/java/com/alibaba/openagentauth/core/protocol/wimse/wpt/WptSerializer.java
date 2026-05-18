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

import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Serializer for Workload Proof Tokens (WPT). Converts structured
 * {@link WorkloadProofToken} objects into signed JWT strings.
 */
public class WptSerializer {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(WptSerializer.class);

    /**
     * Serializes and signs a WorkloadProofToken object to a JWT string.
     * <p>
     * This method builds a JWSObject from the structured WorkloadProofToken,
     * signs it using the provided signer, and returns the serialized JWT string.
     * This approach follows the natural JWT flow of "build → sign → serialize"
     * and eliminates the need for manual string concatenation.
     * </p>
     *
     * @param wpt the WorkloadProofToken object to serialize and sign
     * @param signer the JWSSigner to use for signing
     * @return the signed JWT string representation
     * @throws JOSEException if serialization or signing fails
     */
    public static String serialize(WorkloadProofToken wpt, JWSSigner signer) throws JOSEException {

        // Validate arguments
        ValidationUtils.validateNotNull(wpt, "WorkloadProofToken");
        ValidationUtils.validateNotNull(signer, "JWSSigner");

        try {
            // Build JWSObject from the structured WPT
            JWSObject jwsObject = buildJWSObject(wpt);

            // Sign the JWSObject
            jwsObject.sign(signer);

            // Serialize and return the signed JWT string
            return jwsObject.serialize();

        } catch (Exception e) {
            logger.error("Failed to serialize and sign WorkloadProofToken to JWT string", e);
            throw new JOSEException("Failed to serialize and sign WorkloadProofToken to JWT string", e);
        }
    }

    /**
     * Builds a JWSObject from the structured WorkloadProofToken.
     *
     * @param wpt the WorkloadProofToken object
     * @return the JWSObject ready for signing
     * @throws JOSEException if building fails
     */
    private static JWSObject buildJWSObject(WorkloadProofToken wpt) throws JOSEException {
        try {
            // Build JWSHeader from WPT header
            JWSHeader header = new JWSHeader.Builder(
                    new JWSAlgorithm(wpt.header().algorithm()))
                    .type(new JOSEObjectType(wpt.header().type()))
                    .build();

            // Build JWTClaimsSet from WPT claims
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .expirationTime(wpt.claims().expirationTime())
                    .jwtID(wpt.claims().jwtId())
                    .claim("wth", wpt.claims().workloadTokenHash());

            // Add optional claims
            if (wpt.claims().audience() != null) {
                claimsBuilder.audience(wpt.claims().audience());
            }
            if (wpt.claims().accessTokenHash() != null) {
                claimsBuilder.claim("ath", wpt.claims().accessTokenHash());
            }
            if (wpt.claims().otherTokenHashes() != null) {
                claimsBuilder.claim("oth", wpt.claims().otherTokenHashes());
            }

            JWTClaimsSet claimsSet = claimsBuilder.build();

            // Create JWSObject with header and payload
            return new JWSObject(header, new Payload(claimsSet.toJSONObject()));

        } catch (Exception e) {
            logger.error("Failed to build JWSObject from WPT", e);
            throw new JOSEException("Failed to build JWSObject from WPT", e);
        }
    }
}