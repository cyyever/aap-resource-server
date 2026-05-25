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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WptParser}.
 */
@DisplayName("WPT Parser Tests")
class WptParserTest {

    private WptParser wptParser;
    private OctetKeyPair signingKey;
    private String sampleWit;
    private String sampleAccessToken;

    @BeforeEach
    void setUp() throws JOSEException {
        wptParser = new WptParser();

        signingKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("wpt-signing-key")
                .generate();

        sampleWit = "sample-wit-jwt-string";
        sampleAccessToken = "sample-access-token";
    }

    @Nested
    @DisplayName("parse() - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should parse valid WPT successfully")
        void shouldParseValidWptSuccessfully() throws Exception {
            String wptJwt = createValidWpt();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt).isNotNull();
            assertThat(wpt.claims()).isNotNull();
            assertThat(wpt.jwtString()).isNotNull();
            assertThat(wpt.signature()).isNotNull();
        }

        @Test
        @DisplayName("Should parse WPT with all required claims")
        void shouldParseWptWithAllRequiredClaims() throws Exception {
            String wptJwt = createValidWpt();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt.claims().audience()).isEqualTo("[resource-server]");
            assertThat(wpt.claims().jwtId()).isNotNull();
            assertThat(wpt.claims().workloadTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should parse WPT with optional claims")
        void shouldParseWptWithOptionalClaims() throws Exception {
            String wptJwt = createWptWithOptionalClaims();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt.claims().accessTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should reject WPT with wrong typ header")
        void shouldRejectWptWithWrongTypHeader() throws Exception {
            String wptJwt = createWptWithCustomTyp();
            SignedJWT signedJwt = SignedJWT.parse(wptJwt);
            assertThatThrownBy(() -> wptParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("typ header must be 'wpt+jwt'");
        }
    }

    @Nested
    @DisplayName("parse() - Input Validation")
    class InputValidationTests {

        @Test
        @DisplayName("Should throw exception when signed JWT is null")
        void shouldThrowExceptionWhenSignedJwtIsNull() {
            assertThatThrownBy(() -> wptParser.parse((SignedJWT) null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Signed JWT");
        }

        @Test
        @DisplayName("Should throw exception when WPT is malformed")
        void shouldThrowExceptionWhenWptIsMalformed() {
            String malformedWpt = "not-a-valid-jwt";

            assertThatThrownBy(() -> SignedJWT.parse(malformedWpt))
                    .isInstanceOf(ParseException.class);
        }
    }

    @Nested
    @DisplayName("parse() - Claims Parsing")
    class ClaimsParsingTests {

        @Test
        @DisplayName("Should parse audience claim correctly")
        void shouldParseAudienceClaimCorrectly() throws Exception {
            String wptJwt = createValidWpt();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt.claims().audience()).isEqualTo("[resource-server]");
        }

        @Test
        @DisplayName("Should parse expiration time claim correctly")
        void shouldParseExpirationTimeClaimCorrectly() throws Exception {
            String wptJwt = createValidWpt();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt.claims().expirationTime()).isNotNull();
            assertThat(wpt.claims().expirationTime()).isAfter(new Date());
        }

        @Test
        @DisplayName("Should parse JWT ID claim correctly")
        void shouldParseJwtIdClaimCorrectly() throws Exception {
            String wptJwt = createValidWpt();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt.claims().jwtId()).isNotNull();
        }

        @Test
        @DisplayName("Should parse workload token hash claim correctly")
        void shouldParseWorkloadTokenHashClaimCorrectly() throws Exception {
            String wptJwt = createValidWpt();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt.claims().workloadTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should parse access token hash claim correctly")
        void shouldParseAccessTokenHashClaimCorrectly() throws Exception {
            String wptJwt = createWptWithOptionalClaims();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt.claims().accessTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should handle null optional claims")
        void shouldHandleNullOptionalClaims() throws Exception {
            String wptJwt = createValidWpt();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt.claims().accessTokenHash()).isNull();
        }
    }

    @Nested
    @DisplayName("parse() - Header Parsing")
    class HeaderParsingTests {

        @Test
        @DisplayName("Should reject WPT without typ header")
        void shouldRejectWptWithoutTypHeader() throws Exception {
            String wptJwt = createWptWithoutTyp();
            SignedJWT signedJwt = SignedJWT.parse(wptJwt);
            assertThatThrownBy(() -> wptParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("typ header must be 'wpt+jwt'");
        }

        @Test
        @DisplayName("Should reject WPT signed with non-EdDSA algorithm")
        void shouldRejectWptSignedWithNonEdDsaAlgorithm() throws Exception {
            RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("rs-key").generate();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .audience("resource-server")
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                    .jwtID(java.util.UUID.randomUUID().toString())
                    .claim("wth", computeHash(sampleWit))
                    .build();
            SignedJWT rsaSigned = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(rsaKey.getKeyID())
                            .type(new JOSEObjectType("wpt+jwt"))
                            .build(),
                    claims);
            rsaSigned.sign(new RSASSASigner(rsaKey));

            SignedJWT signedJwt = SignedJWT.parse(rsaSigned.serialize());
            assertThatThrownBy(() -> wptParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("alg header must be 'EdDSA'");
        }

        @Test
        @DisplayName("Should reject WPT with disallowed JOSE header parameter (kid)")
        void shouldRejectWptWithKidHeader() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .audience("resource-server")
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                    .jwtID(java.util.UUID.randomUUID().toString())
                    .claim("wth", computeHash(sampleWit))
                    .build();
            SignedJWT signedJwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                            .keyID(signingKey.getKeyID())
                            .type(new JOSEObjectType("wpt+jwt"))
                            .build(),
                    claims);
            signedJwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(signingKey));

            SignedJWT parsed = SignedJWT.parse(signedJwt.serialize());
            assertThatThrownBy(() -> wptParser.parse(parsed))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("disallowed parameter: kid");
        }
    }

    @Nested
    @DisplayName("parse() - Signature and JWT String")
    class SignatureAndJwtStringTests {

        @Test
        @DisplayName("Should preserve original JWT string")
        void shouldPreserveOriginalJwtString() throws Exception {
            String wptJwt = createValidWpt();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt.jwtString()).isEqualTo(wptJwt);
        }

        @Test
        @DisplayName("Should extract signature correctly")
        void shouldExtractSignatureCorrectly() throws Exception {
            String wptJwt = createValidWpt();

            WorkloadProofToken wpt = wptParser.parse(SignedJWT.parse(wptJwt));

            assertThat(wpt.signature()).isNotNull();
            String[] parts = wptJwt.split("\\.");
            assertThat(parts).hasSize(3);
            assertThat(wpt.signature()).isEqualTo(parts[2]);
        }
    }

    private String createValidWpt() throws JOSEException {
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("resource-server")
                .expirationTime(Date.from(expirationTime))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("wth", computeHash(sampleWit))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                        .type(new JOSEObjectType("wpt+jwt"))
                        .build(),
                claimsSet
        );

        signedJwt.sign(new Ed25519Signer(signingKey));
        return signedJwt.serialize();
    }

    private String createWptWithOptionalClaims() throws JOSEException {
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("resource-server")
                .expirationTime(Date.from(expirationTime))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("wth", computeHash(sampleWit))
                .claim("ath", computeHash(sampleAccessToken))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                        .type(new JOSEObjectType("wpt+jwt"))
                        .build(),
                claimsSet
        );

        signedJwt.sign(new Ed25519Signer(signingKey));
        return signedJwt.serialize();
    }

    private String createWptWithCustomTyp() throws JOSEException {
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("resource-server")
                .expirationTime(Date.from(expirationTime))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("wth", computeHash(sampleWit))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                        .keyID(signingKey.getKeyID())
                        .type(new JOSEObjectType("custom-type"))
                        .build(),
                claimsSet
        );

        signedJwt.sign(new Ed25519Signer(signingKey));
        return signedJwt.serialize();
    }

    private String createWptWithoutTyp() throws JOSEException {
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("resource-server")
                .expirationTime(Date.from(expirationTime))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("wth", computeHash(sampleWit))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claimsSet
        );

        signedJwt.sign(new Ed25519Signer(signingKey));
        return signedJwt.serialize();
    }

    private String computeHash(String input) {
        return "hash-" + java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(input.getBytes());
    }
}
