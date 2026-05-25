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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import ai.shao.aap.rs.core.crypto.key.KeyManager;
import ai.shao.aap.rs.core.model.token.CredentialToken;
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
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link CtValidator}. */
@DisplayName("CT Validator Tests")
class CtValidatorTest {

    private static final String VERIFICATION_KEY_ID = "test-verification-key";

    private CtValidator ctValidator;
    private OctetKeyPair signingKey;
    private OctetKeyPair verificationKey;
    private OctetKeyPair wptPublicKey;
    private TrustDomain trustDomain;
    private KeyManager keyManager;

    @BeforeEach
    void setUp() throws JOSEException {
        signingKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID(VERIFICATION_KEY_ID).generate();
        verificationKey = signingKey.toPublicJWK();

        wptPublicKey =
                new OctetKeyPairGenerator(Curve.Ed25519).keyID("dpop-key").generate().toPublicJWK();

        trustDomain = new TrustDomain("example.com");

        keyManager = mock(KeyManager.class);
        when(keyManager.resolveVerificationKey(anyString())).thenReturn(verificationKey);

        ctValidator = new CtValidator(keyManager, VERIFICATION_KEY_ID, trustDomain);
    }

    @Nested
    @DisplayName("CT Validation - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should validate valid CT successfully")
        void shouldValidateValidWitSuccessfully() throws Exception {
            String witJwt = createValidWit();

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().getSubject()).isEqualTo("agent-001");
        }

        @Test
        @DisplayName("Should return parsed token on successful validation")
        void shouldReturnParsedTokenOnSuccessfulValidation() throws Exception {
            String witJwt = createValidWit();

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().getIssuer()).isEqualTo(trustDomain.domainId());
            assertThat(result.getToken().getConfirmation()).isNotNull();
            assertThat(result.getToken().getConfirmation().jwk()).isNotNull();
        }
    }

    @Nested
    @DisplayName("CT Validation - Signature Verification")
    class SignatureVerificationTests {

        @Test
        @DisplayName("Should reject CT with invalid signature")
        void shouldRejectWitWithInvalidSignature() throws Exception {
            String witJwt = createValidWit();
            String tamperedWit = tamperWithSignature(witJwt);

            TokenValidationResult<CredentialToken> result = ctValidator.validate(tamperedWit);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Invalid CT signature");
        }
    }

    @Nested
    @DisplayName("CT Validation - Expiration")
    class ExpirationTests {

        @Test
        @DisplayName("Should reject expired CT")
        void shouldRejectExpiredWit() throws Exception {
            String witJwt = createExpiredWit();

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("CT has expired");
        }

        @Test
        @DisplayName("Should reject CT without expiration time")
        void shouldRejectWitWithoutExpirationTime() throws Exception {
            String witJwt = createWitWithoutExpiration();

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("CT has expired");
        }
    }

    @Nested
    @DisplayName("CT Validation - Trust Domain")
    class TrustDomainTests {

        @Test
        @DisplayName("Should reject CT with wrong trust domain")
        void shouldRejectWitWithWrongTrustDomain() throws Exception {
            String witJwt =
                    signedWit(
                            "wrong-domain.com",
                            "agent-001",
                            Instant.now().plusSeconds(3600),
                            wptPublicKey.toJSONObject(),
                            signingKey);

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Invalid trust domain");
        }

        @Test
        @DisplayName("Should accept CT with correct trust domain")
        void shouldAcceptWitWithCorrectTrustDomain() throws Exception {
            String witJwt = createValidWit();

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("CT Validation - Required Claims")
    class RequiredClaimsTests {

        @Test
        @DisplayName("Should reject CT missing subject claim")
        void shouldRejectWitMissingSubjectClaim() throws Exception {
            String witJwt = createWitWithoutSubject();

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Missing required claims");
        }

        @Test
        @DisplayName("Should reject CT missing expiration claim")
        void shouldRejectWitMissingExpirationClaim() throws Exception {
            String witJwt = createWitWithoutExpiration();

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should reject CT missing cnf claim")
        void shouldRejectWitMissingCnfClaim() throws Exception {
            String witJwt = createWitWithoutCnf();

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Missing required claims");
        }
    }

    @Nested
    @DisplayName("CT Validation - Cnf Claim")
    class CnfClaimTests {

        @Test
        @DisplayName("Should reject CT with invalid cnf.jwk")
        void shouldRejectWitWithInvalidCnfJwk() throws Exception {
            String witJwt = createWitWithInvalidCnfJwk();

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Invalid cnf claim");
        }

        @Test
        @DisplayName("Should accept CT with valid cnf.jwk")
        void shouldAcceptWitWithValidCnfJwk() throws Exception {
            String witJwt = createValidWit();

            TokenValidationResult<CredentialToken> result = ctValidator.validate(witJwt);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken().getConfirmation().jwk()).isNotNull();
        }
    }

    @Nested
    @DisplayName("CT Validation - Input Validation")
    class InputValidationTests {

        @Test
        @DisplayName("Should reject null CT")
        void shouldRejectNullWit() throws ParseException {
            TokenValidationResult<CredentialToken> result = ctValidator.validate(null);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("CT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject empty CT")
        void shouldRejectEmptyWit() throws ParseException {
            TokenValidationResult<CredentialToken> result = ctValidator.validate("");

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("CT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject whitespace CT")
        void shouldRejectWhitespaceWit() throws ParseException {
            TokenValidationResult<CredentialToken> result = ctValidator.validate("   ");

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("CT cannot be null or empty");
        }
    }

    private String createValidWit() throws JOSEException {
        return signedWit(
                trustDomain.domainId(),
                "agent-001",
                Instant.now().plusSeconds(3600),
                wptPublicKey.toJSONObject(),
                signingKey);
    }

    private String createExpiredWit() throws JOSEException {
        return signedWit(
                trustDomain.domainId(),
                "agent-001",
                Instant.now().minusSeconds(3600),
                wptPublicKey.toJSONObject(),
                signingKey);
    }

    private String createWitWithoutExpiration() throws JOSEException {
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", wptPublicKey.toJSONObject());
        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .issuer(trustDomain.domainId())
                        .subject("agent-001")
                        .jwtID(UUID.randomUUID().toString())
                        .claim("cnf", cnf)
                        .build();
        return sign(claims, signingKey);
    }

    private String createWitWithoutSubject() throws JOSEException {
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", wptPublicKey.toJSONObject());
        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .issuer(trustDomain.domainId())
                        .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                        .jwtID(UUID.randomUUID().toString())
                        .claim("cnf", cnf)
                        .build();
        return sign(claims, signingKey);
    }

    private String createWitWithoutCnf() throws JOSEException {
        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .issuer(trustDomain.domainId())
                        .subject("agent-001")
                        .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                        .jwtID(UUID.randomUUID().toString())
                        .build();
        return sign(claims, signingKey);
    }

    private String createWitWithInvalidCnfJwk() throws JOSEException {
        Map<String, Object> invalidJwk = new HashMap<>();
        invalidJwk.put("kty", "INVALID");
        invalidJwk.put("x", "invalid-x");
        return signedWit(
                trustDomain.domainId(),
                "agent-001",
                Instant.now().plusSeconds(3600),
                invalidJwk,
                signingKey);
    }

    private String tamperWithSignature(String witJwt) {
        if (witJwt.length() > 0) {
            String[] parts = witJwt.split("\\.");
            if (parts.length == 3) {
                String signature = parts[2];
                String tamperedSignature = signature.replace('A', 'B').replace('a', 'b');
                return parts[0] + "." + parts[1] + "." + tamperedSignature;
            }
        }
        return witJwt;
    }

    private static String signedWit(
            String issuer,
            String subject,
            Instant expiration,
            Map<String, Object> cnfJwk,
            OctetKeyPair signingKey)
            throws JOSEException {
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", cnfJwk);
        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .issuer(issuer)
                        .subject(subject)
                        .expirationTime(Date.from(expiration))
                        .jwtID(UUID.randomUUID().toString())
                        .claim("cnf", cnf)
                        .build();
        return sign(claims, signingKey);
    }

    private static String sign(JWTClaimsSet claims, OctetKeyPair signingKey) throws JOSEException {
        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                        .type(new JOSEObjectType("ct+jwt"))
                        .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new Ed25519Signer(signingKey));
        return jwt.serialize();
    }
}
