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

import static org.assertj.core.api.Assertions.*;

import ai.shao.aap.rs.core.model.token.CredentialToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link CtParser}. */
@DisplayName("CT Parser Tests")
class CtParserTest {

    private CtParser ctParser;
    private OctetKeyPair signingKey;
    private OctetKeyPair wptPublicKey;

    @BeforeEach
    void setUp() throws JOSEException {
        ctParser = new CtParser();

        signingKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("ct-signing-key").generate();

        wptPublicKey =
                new OctetKeyPairGenerator(Curve.Ed25519).keyID("dpop-key").generate().toPublicJWK();
    }

    @Nested
    @DisplayName("CT Parsing - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should parse valid CT with all claims")
        void shouldParseValidWitWithAllClaims() throws Exception {
            SignedJWT signedJwt = createSignedJwtWithAllClaims();

            CredentialToken ct = ctParser.parse(signedJwt);

            assertThat(ct).isNotNull();
            assertThat(ct.getSubject()).isEqualTo("agent-001");
            assertThat(ct.getIssuer()).isEqualTo("example.com");
            assertThat(ct.getExpirationTime()).isNotNull();
            assertThat(ct.getJwtId()).isNotNull();
            assertThat(ct.getConfirmation()).isNotNull();
        }

        @Test
        @DisplayName("Should parse cnf claim with jwk")
        void shouldParseCnfClaimWithJwk() throws Exception {
            SignedJWT signedJwt = createSignedJwtWithCnfJwk();

            CredentialToken ct = ctParser.parse(signedJwt);

            assertThat(ct.getConfirmation()).isNotNull();
            assertThat(ct.getConfirmation().jwk()).isNotNull();
            assertThat(ct.getConfirmation().jwk().x()).isNotBlank();
        }

        @Test
        @DisplayName("Should parse CT without optional claims")
        void shouldParseWitWithoutOptionalClaims() throws Exception {
            SignedJWT signedJwt = createSignedJwtWithRequiredClaimsOnly();

            CredentialToken ct = ctParser.parse(signedJwt);

            assertThat(ct).isNotNull();
            assertThat(ct.getSubject()).isNotNull();
            assertThat(ct.getExpirationTime()).isNotNull();
            assertThat(ct.getConfirmation()).isNotNull();
            assertThat(ct.getIssuer()).isNull();
            assertThat(ct.getJwtId()).isNull();
        }
    }

    @Nested
    @DisplayName("CT Parsing - Error Handling")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should throw exception when signedJwt is null")
        void shouldThrowExceptionWhenSignedJwtIsNull() {
            assertThatThrownBy(() -> ctParser.parse(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Signed JWT cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when cnf claim missing jwk")
        void shouldThrowExceptionWhenCnfClaimMissingJwk() throws Exception {
            SignedJWT signedJwt = createSignedJwtWithCnfMissingJwk();

            assertThatThrownBy(() -> ctParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("cnf claim missing required 'jwk' field");
        }

        @Test
        @DisplayName("Should throw exception when cnf.jwk is invalid")
        void shouldThrowExceptionWhenCnfJwkIsInvalid() throws Exception {
            SignedJWT signedJwt = createSignedJwtWithInvalidCnfJwk();

            assertThatThrownBy(() -> ctParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("Failed to parse cnf.jwk claim");
        }

        @Test
        @DisplayName("Should throw exception when cnf claim missing")
        void shouldThrowExceptionWhenCnfClaimMissing() throws Exception {
            SignedJWT signedJwt = createSignedJwtWithoutCnf();

            assertThatThrownBy(() -> ctParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("missing required claim: cnf");
        }

        @Test
        @DisplayName("Should reject CT signed with non-EdDSA algorithm")
        void shouldRejectWitSignedWithNonEdDsaAlgorithm() throws Exception {
            RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("rs-key").generate();
            JWTClaimsSet claims =
                    new JWTClaimsSet.Builder()
                            .subject("agent-001")
                            .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                            .build();
            SignedJWT rsaSigned =
                    new SignedJWT(
                            new JWSHeader.Builder(JWSAlgorithm.RS256)
                                    .keyID(rsaKey.getKeyID())
                                    .type(new JOSEObjectType("ct+jwt"))
                                    .build(),
                            claims);
            rsaSigned.sign(new RSASSASigner(rsaKey));

            assertThatThrownBy(() -> ctParser.parse(rsaSigned))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("alg header must be 'EdDSA'");
        }

        @Test
        @DisplayName("Should reject CT with disallowed JOSE header parameter (kid)")
        void shouldRejectWitWithKidHeader() throws Exception {
            JWTClaimsSet claims =
                    new JWTClaimsSet.Builder()
                            .subject("agent-001")
                            .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                            .build();
            SignedJWT signedJwt =
                    new SignedJWT(
                            new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                                    .keyID(signingKey.getKeyID())
                                    .type(new JOSEObjectType("ct+jwt"))
                                    .build(),
                            claims);
            signedJwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(signingKey));

            assertThatThrownBy(() -> ctParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("disallowed parameter: kid");
        }
    }

    private SignedJWT createSignedJwtWithAllClaims() throws Exception {
        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", createJwkMap());

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .issuer("example.com")
                        .subject("agent-001")
                        .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                        .jwtID("test-jti-001")
                        .claim("cnf", cnfClaim)
                        .build();

        return signJwt(claimsSet);
    }

    private SignedJWT createSignedJwtWithCnfJwk() throws Exception {
        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", createJwkMap());

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject("agent-001")
                        .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                        .claim("cnf", cnfClaim)
                        .build();

        return signJwt(claimsSet);
    }

    private SignedJWT createSignedJwtWithRequiredClaimsOnly() throws Exception {
        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", createJwkMap());

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject("agent-001")
                        .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                        .claim("cnf", cnfClaim)
                        .build();

        return signJwt(claimsSet);
    }

    private SignedJWT createSignedJwtWithCnfMissingJwk() throws Exception {
        Map<String, Object> cnfClaim = new HashMap<>();

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject("agent-001")
                        .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                        .claim("cnf", cnfClaim)
                        .build();

        return signJwt(claimsSet);
    }

    private SignedJWT createSignedJwtWithInvalidCnfJwk() throws Exception {
        Map<String, Object> cnfClaim = new HashMap<>();
        Map<String, Object> invalidJwk = new HashMap<>();
        invalidJwk.put("kty", "INVALID");
        cnfClaim.put("jwk", invalidJwk);

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject("agent-001")
                        .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                        .claim("cnf", cnfClaim)
                        .build();

        return signJwt(claimsSet);
    }

    private SignedJWT createSignedJwtWithoutCnf() throws Exception {
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject("agent-001")
                        .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                        .build();

        return signJwt(claimsSet);
    }

    private Map<String, Object> createJwkMap() {
        Map<String, Object> jwkMap = wptPublicKey.toJSONObject();
        jwkMap.put("alg", "EdDSA");
        return jwkMap;
    }

    private SignedJWT signJwt(JWTClaimsSet claimsSet) throws Exception {
        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                                .type(new JOSEObjectType("ct+jwt"))
                                .build(),
                        claimsSet);
        signedJwt.sign(new Ed25519Signer(signingKey));
        return signedJwt;
    }
}
