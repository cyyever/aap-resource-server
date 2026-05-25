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
import com.alibaba.openagentauth.core.trust.TrustDomain;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WptValidator}.
 */
@DisplayName("WPT Validator Tests")
class WptValidatorTest {

    private WptValidator wptValidator;
    private OctetKeyPair witSigningKey;
    private OctetKeyPair wptPublicKey;
    private OctetKeyPair wptPrivateKey;
    private TrustDomain trustDomain;

    @BeforeEach
    void setUp() throws JOSEException {
        witSigningKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("wit-signing-key")
                .generate();

        wptPrivateKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("wpt-key")
                .generate();
        wptPublicKey = wptPrivateKey.toPublicJWK();

        trustDomain = new TrustDomain("wimse://example.com");
        wptValidator = new WptValidator();
    }

    @Nested
    @DisplayName("WPT Validation - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should validate valid WPT successfully")
        void shouldValidateValidWptSuccessfully() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = signedWpt(wit, wptPrivateKey, 300);

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken()).isNotNull();
        }

        @Test
        @DisplayName("Should return parsed WPT on successful validation")
        void shouldReturnParsedWptOnSuccessfulValidation() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = signedWpt(wit, wptPrivateKey, 300);

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().claims().workloadTokenHash()).isNotNull();
        }
    }

    @Nested
    @DisplayName("WPT Validation - Expiration")
    class ExpirationTests {

        @Test
        @DisplayName("Should reject expired WPT")
        void shouldRejectExpiredWpt() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = createExpiredWpt();

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WPT expired");
        }

        @Test
        @DisplayName("Should accept non-expired WPT")
        void shouldAcceptNonExpiredWpt() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = signedWpt(wit, wptPrivateKey, 300);

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("WPT Validation - Signature Verification")
    class SignatureVerificationTests {

        @Test
        @DisplayName("Should reject WPT with invalid signature")
        void shouldRejectWptWithInvalidSignature() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = signedWpt(wit, wptPrivateKey, 300);

            WorkloadProofToken tamperedWpt = tamperWithWptSignature(wpt);

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(tamperedWpt, wit);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WPT signature verification failed");
        }

        @Test
        @DisplayName("Should accept WPT with valid signature")
        void shouldAcceptWptWithValidSignature() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = signedWpt(wit, wptPrivateKey, 300);

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("WPT Validation - Required Claims")
    class RequiredClaimsTests {

        @Test
        @DisplayName("Should reject WPT missing wth claim")
        void shouldRejectWptMissingWthClaim() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = createWptWithoutWth();

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("required claim");
        }

        @Test
        @DisplayName("Should accept WPT with wth claim")
        void shouldAcceptWptWithWthClaim() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = signedWpt(wit, wptPrivateKey, 300);

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken().claims().workloadTokenHash()).isNotNull();
        }
    }

    @Nested
    @DisplayName("WPT Validation - WTH Verification")
    class WthVerificationTests {

        @Test
        @DisplayName("Should reject WPT with mismatched wth")
        void shouldRejectWptWithMismatchedWth() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = signedWpt(wit, wptPrivateKey, 300);

            WorkloadIdentityToken differentWit = createValidWit("agent-002");

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, differentWit);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("does not match WIT hash");
        }

        @Test
        @DisplayName("Should accept WPT with matching wth")
        void shouldAcceptWptWithMatchingWth() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = signedWpt(wit, wptPrivateKey, 300);

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("WPT Validation - Input Validation")
    class InputValidationTests {

        @Test
        @DisplayName("Should reject null WPT")
        void shouldRejectNullWpt() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(null, wit);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WPT cannot be null");
        }

        @Test
        @DisplayName("Should reject null WIT")
        void shouldRejectNullWit() throws Exception {
            WorkloadIdentityToken wit = createValidWit("agent-001");
            WorkloadProofToken wpt = signedWpt(wit, wptPrivateKey, 300);

            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, null);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WIT cannot be null");
        }
    }

    private WorkloadIdentityToken createValidWit(String subject) throws JOSEException {
        return signedWit(trustDomain.getDomainId(), subject,
                Date.from(Instant.now().plusSeconds(3600)),
                wptPublicKey, witSigningKey);
    }

    private static WorkloadIdentityToken signedWit(String issuer, String subject, Date expiration,
                                                   OctetKeyPair cnfPublicKey, OctetKeyPair signingKey)
            throws JOSEException {
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", cnfPublicKey.toJSONObject());
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .expirationTime(expiration)
                .jwtID(UUID.randomUUID().toString())
                .claim("cnf", cnf)
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new JOSEObjectType("wit+jwt"))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(signingKey));
        String jwtString = jwt.serialize();

        Jwk cnfJwk = Jwk.builder().x(cnfPublicKey.getX().toString()).keyId(cnfPublicKey.getKeyID()).build();
        WorkloadIdentityToken.Claims.Confirmation confirmation =
                WorkloadIdentityToken.Claims.Confirmation.builder().jwk(cnfJwk).build();
        WorkloadIdentityToken.Claims witClaims = WorkloadIdentityToken.Claims.builder()
                .issuer(issuer)
                .subject(subject)
                .expirationTime(expiration)
                .jwtId(UUID.randomUUID().toString())
                .confirmation(confirmation)
                .build();
        String[] parts = jwtString.split("\\.");
        String signature = parts.length > 2 ? parts[2] : "";
        return WorkloadIdentityToken.builder()
                .claims(witClaims)
                .signature(signature)
                .jwtString(jwtString)
                .build();
    }

    private static WorkloadProofToken signedWpt(WorkloadIdentityToken wit, OctetKeyPair signingKey,
                                                long expirationSeconds) throws JOSEException {
        String wth = JwtHashUtil.computeWitHash(wit.jwtString());
        Date expiration = Date.from(Instant.now().plusSeconds(expirationSeconds));
        String jti = UUID.randomUUID().toString();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .expirationTime(expiration)
                .jwtID(jti)
                .claim("wth", wth)
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .type(new JOSEObjectType("wpt+jwt"))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(signingKey));
        String jwtString = jwt.serialize();
        String[] parts = jwtString.split("\\.");
        String signature = parts.length > 2 ? parts[2] : "";

        WorkloadProofToken.Claims wptClaims = WorkloadProofToken.Claims.builder()
                .expirationTime(expiration)
                .jwtId(jti)
                .workloadTokenHash(wth)
                .build();
        return WorkloadProofToken.builder()
                .claims(wptClaims)
                .signature(signature)
                .jwtString(jwtString)
                .build();
    }

    private WorkloadProofToken createExpiredWpt() {
        return WorkloadProofToken.builder()
                .claims(WorkloadProofToken.Claims.builder()
                        .expirationTime(Date.from(Instant.now().minusSeconds(300)))
                        .jwtId(UUID.randomUUID().toString())
                        .workloadTokenHash("test-wth-hash")
                        .build())
                .signature("test-signature")
                .jwtString("test.jwt.string")
                .build();
    }

    private WorkloadProofToken createWptWithoutWth() {
        return WorkloadProofToken.builder()
                .claims(WorkloadProofToken.Claims.builder()
                        .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                        .jwtId(UUID.randomUUID().toString())
                        .workloadTokenHash("   ")
                        .build())
                .signature("test-signature")
                .jwtString("test.jwt.string")
                .build();
    }

    private WorkloadProofToken tamperWithWptSignature(WorkloadProofToken wpt) {
        String jwtString = wpt.jwtString();
        if (jwtString != null && jwtString.contains(".")) {
            int lastDotIndex = jwtString.lastIndexOf(".");
            String tamperedJwtString = jwtString.substring(0, lastDotIndex + 1) + "tampered" + jwtString.substring(lastDotIndex + 1);

            return WorkloadProofToken.builder()
                    .claims(wpt.claims())
                    .signature(wpt.signature() + "tampered")
                    .jwtString(tamperedJwtString)
                    .build();
        }

        String tamperedSignature = wpt.signature() + "tampered";
        return WorkloadProofToken.builder()
                .claims(wpt.claims())
                .signature(tamperedSignature)
                .jwtString(wpt.jwtString())
                .build();
    }
}
