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

import static org.assertj.core.api.Assertions.assertThat;

import ai.shao.aap.rs.core.crypto.JwtHashUtil;
import ai.shao.aap.rs.core.model.jwk.Jwk;
import ai.shao.aap.rs.core.model.token.CredentialToken;
import ai.shao.aap.rs.core.model.token.DpopToken;
import ai.shao.aap.rs.core.token.common.TokenValidationResult;
import ai.shao.aap.rs.core.trust.TrustDomain;
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
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link DpopValidator}. */
@DisplayName("DPoP Validator Tests")
class DpopValidatorTest {

    private DpopValidator dpopValidator;
    private OctetKeyPair witSigningKey;
    private OctetKeyPair wptPublicKey;
    private OctetKeyPair wptPrivateKey;
    private TrustDomain trustDomain;

    @BeforeEach
    void setUp() throws JOSEException {
        witSigningKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("ct-signing-key").generate();

        wptPrivateKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("dpop-key").generate();
        wptPublicKey = wptPrivateKey.toPublicJWK();

        trustDomain = new TrustDomain("example.com");
        dpopValidator = new DpopValidator();
    }

    @Nested
    @DisplayName("DPoP Validation - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should validate valid DPoP successfully")
        void shouldValidateValidWptSuccessfully() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = signedWpt(ct, wptPrivateKey, 300);

            TokenValidationResult<DpopToken> result = dpopValidator.validate(dpop, ct);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken()).isNotNull();
        }

        @Test
        @DisplayName("Should return parsed DPoP on successful validation")
        void shouldReturnParsedWptOnSuccessfulValidation() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = signedWpt(ct, wptPrivateKey, 300);

            TokenValidationResult<DpopToken> result = dpopValidator.validate(dpop, ct);

            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().claims().workloadTokenHash()).isNotNull();
        }
    }

    @Nested
    @DisplayName("DPoP Validation - Expiration")
    class ExpirationTests {

        @Test
        @DisplayName("Should reject expired DPoP")
        void shouldRejectExpiredWpt() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = createExpiredWpt();

            TokenValidationResult<DpopToken> result = dpopValidator.validate(dpop, ct);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("DPoP expired");
        }

        @Test
        @DisplayName("Should accept non-expired DPoP")
        void shouldAcceptNonExpiredWpt() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = signedWpt(ct, wptPrivateKey, 300);

            TokenValidationResult<DpopToken> result = dpopValidator.validate(dpop, ct);

            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("DPoP Validation - Signature Verification")
    class SignatureVerificationTests {

        @Test
        @DisplayName("Should reject DPoP with invalid signature")
        void shouldRejectWptWithInvalidSignature() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = signedWpt(ct, wptPrivateKey, 300);

            DpopToken tamperedWpt = tamperWithWptSignature(dpop);

            TokenValidationResult<DpopToken> result = dpopValidator.validate(tamperedWpt, ct);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("DPoP signature verification failed");
        }

        @Test
        @DisplayName("Should accept DPoP with valid signature")
        void shouldAcceptWptWithValidSignature() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = signedWpt(ct, wptPrivateKey, 300);

            TokenValidationResult<DpopToken> result = dpopValidator.validate(dpop, ct);

            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("DPoP Validation - Required Claims")
    class RequiredClaimsTests {

        @Test
        @DisplayName("Should reject DPoP missing wth claim")
        void shouldRejectWptMissingWthClaim() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = createWptWithoutWth();

            TokenValidationResult<DpopToken> result = dpopValidator.validate(dpop, ct);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("required claim");
        }

        @Test
        @DisplayName("Should accept DPoP with wth claim")
        void shouldAcceptWptWithWthClaim() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = signedWpt(ct, wptPrivateKey, 300);

            TokenValidationResult<DpopToken> result = dpopValidator.validate(dpop, ct);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken().claims().workloadTokenHash()).isNotNull();
        }
    }

    @Nested
    @DisplayName("DPoP Validation - WTH Verification")
    class WthVerificationTests {

        @Test
        @DisplayName("Should reject DPoP with mismatched wth")
        void shouldRejectWptWithMismatchedWth() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = signedWpt(ct, wptPrivateKey, 300);

            CredentialToken differentWit = createValidWit("agent-002");

            TokenValidationResult<DpopToken> result = dpopValidator.validate(dpop, differentWit);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("does not match CT hash");
        }

        @Test
        @DisplayName("Should accept DPoP with matching wth")
        void shouldAcceptWptWithMatchingWth() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = signedWpt(ct, wptPrivateKey, 300);

            TokenValidationResult<DpopToken> result = dpopValidator.validate(dpop, ct);

            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("DPoP Validation - Input Validation")
    class InputValidationTests {

        @Test
        @DisplayName("Should reject null DPoP")
        void shouldRejectNullWpt() throws Exception {
            CredentialToken ct = createValidWit("agent-001");

            TokenValidationResult<DpopToken> result = dpopValidator.validate(null, ct);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("DPoP cannot be null");
        }

        @Test
        @DisplayName("Should reject null CT")
        void shouldRejectNullWit() throws Exception {
            CredentialToken ct = createValidWit("agent-001");
            DpopToken dpop = signedWpt(ct, wptPrivateKey, 300);

            TokenValidationResult<DpopToken> result = dpopValidator.validate(dpop, null);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("CT cannot be null");
        }
    }

    private CredentialToken createValidWit(String subject) throws JOSEException {
        return signedWit(
                trustDomain.domainId(),
                subject,
                Instant.now().plusSeconds(3600),
                wptPublicKey,
                witSigningKey);
    }

    private static CredentialToken signedWit(
            String issuer,
            String subject,
            Instant expiration,
            OctetKeyPair cnfPublicKey,
            OctetKeyPair signingKey)
            throws JOSEException {
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", cnfPublicKey.toJSONObject());
        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .issuer(issuer)
                        .subject(subject)
                        .expirationTime(Date.from(expiration))
                        .jwtID(UUID.randomUUID().toString())
                        .claim("cnf", cnf)
                        .build();
        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                        .type(new JOSEObjectType("ct+jwt"))
                        .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(signingKey));
        String jwtString = jwt.serialize();

        Jwk cnfJwk =
                Jwk.builder()
                        .x(cnfPublicKey.getX().toString())
                        .keyId(cnfPublicKey.getKeyID())
                        .build();
        CredentialToken.Claims.Confirmation confirmation =
                CredentialToken.Claims.Confirmation.builder().jwk(cnfJwk).build();
        CredentialToken.Claims witClaims =
                CredentialToken.Claims.builder()
                        .issuer(issuer)
                        .subject(subject)
                        .expirationTime(expiration)
                        .jwtId(UUID.randomUUID().toString())
                        .confirmation(confirmation)
                        .build();
        String[] parts = jwtString.split("\\.");
        String signature = parts.length > 2 ? parts[2] : "";
        return CredentialToken.builder()
                .claims(witClaims)
                .signature(signature)
                .jwtString(jwtString)
                .build();
    }

    private static DpopToken signedWpt(
            CredentialToken ct, OctetKeyPair signingKey, long expirationSeconds)
            throws JOSEException {
        String wth = JwtHashUtil.computeWitHash(ct.jwtString());
        Instant expiration = Instant.now().plusSeconds(expirationSeconds);
        String jti = UUID.randomUUID().toString();

        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .expirationTime(Date.from(expiration))
                        .jwtID(jti)
                        .claim("wth", wth)
                        .build();
        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                        .type(new JOSEObjectType("dpop+jwt"))
                        .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(signingKey));
        String jwtString = jwt.serialize();
        String[] parts = jwtString.split("\\.");
        String signature = parts.length > 2 ? parts[2] : "";

        DpopToken.Claims wptClaims =
                DpopToken.Claims.builder()
                        .expirationTime(expiration)
                        .jwtId(jti)
                        .workloadTokenHash(wth)
                        .build();
        return DpopToken.builder()
                .claims(wptClaims)
                .signature(signature)
                .jwtString(jwtString)
                .build();
    }

    private DpopToken createExpiredWpt() {
        return DpopToken.builder()
                .claims(
                        DpopToken.Claims.builder()
                                .expirationTime(Instant.now().minusSeconds(300))
                                .jwtId(UUID.randomUUID().toString())
                                .workloadTokenHash("test-wth-hash")
                                .build())
                .signature("test-signature")
                .jwtString("test.jwt.string")
                .build();
    }

    private DpopToken createWptWithoutWth() {
        return DpopToken.builder()
                .claims(
                        DpopToken.Claims.builder()
                                .expirationTime(Instant.now().plusSeconds(300))
                                .jwtId(UUID.randomUUID().toString())
                                .workloadTokenHash("   ")
                                .build())
                .signature("test-signature")
                .jwtString("test.jwt.string")
                .build();
    }

    private DpopToken tamperWithWptSignature(DpopToken dpop) {
        String jwtString = dpop.jwtString();
        if (jwtString != null && jwtString.contains(".")) {
            int lastDotIndex = jwtString.lastIndexOf(".");
            String tamperedJwtString =
                    jwtString.substring(0, lastDotIndex + 1)
                            + "tampered"
                            + jwtString.substring(lastDotIndex + 1);

            return DpopToken.builder()
                    .claims(dpop.claims())
                    .signature(dpop.signature() + "tampered")
                    .jwtString(tamperedJwtString)
                    .build();
        }

        String tamperedSignature = dpop.signature() + "tampered";
        return DpopToken.builder()
                .claims(dpop.claims())
                .signature(tamperedSignature)
                .jwtString(dpop.jwtString())
                .build();
    }
}
