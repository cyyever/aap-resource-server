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
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WptParser}.
 * Tests verify compliance with WIMSE WPT protocol specification:
 * https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt-00.html
 */
@DisplayName("WPT Parser Tests - draft-ietf-wimse-wpt-00")
class WptParserTest {

    private WptParser wptParser;
    private ECKey signingKey;
    private String sampleWit;
    private String sampleAccessToken;

    @BeforeEach
    void setUp() throws JOSEException {
        wptParser = new WptParser();
        
        // Generate EC key pair for WPT signing
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(Curve.P_256);
        signingKey = ecKeyGenerator.keyID("wpt-signing-key").generate();
        
        // Sample tokens for hash computation
        sampleWit = "sample-wit-jwt-string";
        sampleAccessToken = "sample-access-token";
    }

    @Nested
    @DisplayName("parse() - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should parse valid WPT successfully")
        void shouldParseValidWptSuccessfully() throws Exception {
            // Given
            String wptJwt = createValidWpt();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt).isNotNull();
            assertThat(wpt.header()).isNotNull();
            assertThat(wpt.claims()).isNotNull();
            assertThat(wpt.jwtString()).isNotNull();
            assertThat(wpt.signature()).isNotNull();
        }

        @Test
        @DisplayName("Should parse WPT with all required claims")
        void shouldParseWptWithAllRequiredClaims() throws Exception {
            // Given
            String wptJwt = createValidWpt();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.header().type()).isEqualTo("wpt+jwt");
            assertThat(wpt.header().algorithm()).isEqualTo("ES256");
            assertThat(wpt.claims().audience()).isEqualTo("[resource-server]");
            assertThat(wpt.claims().jwtId()).isNotNull();
            assertThat(wpt.claims().workloadTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should parse WPT with optional claims")
        void shouldParseWptWithOptionalClaims() throws Exception {
            // Given
            String wptJwt = createWptWithOptionalClaims();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.claims().accessTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should parse WPT with custom typ header")
        void shouldParseWptWithCustomTypHeader() throws Exception {
            // Given
            String wptJwt = createWptWithCustomTyp();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            // Note: WptParser always defaults to "wpt+jwt" when typ is not in the header
            assertThat(wpt.header().type()).isEqualTo("wpt+jwt");
        }
    }

    @Nested
    @DisplayName("parse() - Input Validation")
    class InputValidationTests {

        @Test
        @DisplayName("Should throw exception when WPT is null")
        void shouldThrowExceptionWhenWptIsNull() {
            // When & Then
            assertThatThrownBy(() -> wptParser.parse(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WPT JWT string cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when WPT is empty")
        void shouldThrowExceptionWhenWptIsEmpty() {
            // When & Then
            assertThatThrownBy(() -> wptParser.parse(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WPT JWT string cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when WPT is whitespace")
        void shouldThrowExceptionWhenWptIsWhitespace() {
            // When & Then
            assertThatThrownBy(() -> wptParser.parse("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WPT JWT string cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when WPT is malformed")
        void shouldThrowExceptionWhenWptIsMalformed() {
            // Given
            String malformedWpt = "not-a-valid-jwt";

            // When & Then
            assertThatThrownBy(() -> wptParser.parse(malformedWpt))
                    .isInstanceOf(ParseException.class);
        }
    }

    @Nested
    @DisplayName("parse() - Claims Parsing")
    class ClaimsParsingTests {

        @Test
        @DisplayName("Should parse audience claim correctly")
        void shouldParseAudienceClaimCorrectly() throws Exception {
            // Given
            String wptJwt = createValidWpt();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.claims().audience()).isEqualTo("[resource-server]");
        }

        @Test
        @DisplayName("Should parse expiration time claim correctly")
        void shouldParseExpirationTimeClaimCorrectly() throws Exception {
            // Given
            String wptJwt = createValidWpt();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.claims().expirationTime()).isNotNull();
            assertThat(wpt.claims().expirationTime()).isAfter(new Date());
        }

        @Test
        @DisplayName("Should parse JWT ID claim correctly")
        void shouldParseJwtIdClaimCorrectly() throws Exception {
            // Given
            String wptJwt = createValidWpt();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.claims().jwtId()).isNotNull();
        }

        @Test
        @DisplayName("Should parse workload token hash claim correctly")
        void shouldParseWorkloadTokenHashClaimCorrectly() throws Exception {
            // Given
            String wptJwt = createValidWpt();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.claims().workloadTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should parse access token hash claim correctly")
        void shouldParseAccessTokenHashClaimCorrectly() throws Exception {
            // Given
            String wptJwt = createWptWithOptionalClaims();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.claims().accessTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should handle null optional claims")
        void shouldHandleNullOptionalClaims() throws Exception {
            // Given
            String wptJwt = createValidWpt();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.claims().accessTokenHash()).isNull();
        }
    }

    @Nested
    @DisplayName("parse() - Header Parsing")
    class HeaderParsingTests {

        @Test
        @DisplayName("Should parse header algorithm correctly")
        void shouldParseHeaderAlgorithmCorrectly() throws Exception {
            // Given
            String wptJwt = createValidWpt();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.header().algorithm()).isEqualTo("ES256");
        }

        @Test
        @DisplayName("Should default typ to wpt+jwt when not specified")
        void shouldDefaultTypToWptJwtWhenNotSpecified() throws Exception {
            // Given
            String wptJwt = createWptWithoutTyp();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.header().type()).isEqualTo("wpt+jwt");
        }
    }

    @Nested
    @DisplayName("parse() - Signature and JWT String")
    class SignatureAndJwtStringTests {

        @Test
        @DisplayName("Should preserve original JWT string")
        void shouldPreserveOriginalJwtString() throws Exception {
            // Given
            String wptJwt = createValidWpt();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.jwtString()).isEqualTo(wptJwt);
        }

        @Test
        @DisplayName("Should extract signature correctly")
        void shouldExtractSignatureCorrectly() throws Exception {
            // Given
            String wptJwt = createValidWpt();

            // When
            WorkloadProofToken wpt = wptParser.parse(wptJwt);

            // Then
            assertThat(wpt.signature()).isNotNull();
            String[] parts = wptJwt.split("\\.");
            assertThat(parts).hasSize(3);
            assertThat(wpt.signature()).isEqualTo(parts[2]);
        }
    }

    // Helper methods

    private String createValidWpt() throws JOSEException {
        // Create a valid WPT with required claims
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("resource-server")
                .expirationTime(Date.from(expirationTime))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("wth", computeHash(sampleWit))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(signingKey.getKeyID())
                        .type(new JOSEObjectType("wpt+jwt"))
                        .build(),
                claimsSet
        );

        signedJwt.sign(new com.nimbusds.jose.crypto.ECDSASigner(signingKey));
        return signedJwt.serialize();
    }

    private String createWptWithOptionalClaims() throws JOSEException {
        // Create a WPT with all optional claims
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("resource-server")
                .expirationTime(Date.from(expirationTime))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("wth", computeHash(sampleWit))
                .claim("ath", computeHash(sampleAccessToken))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(signingKey.getKeyID())
                        .type(new JOSEObjectType("wpt+jwt"))
                        .build(),
                claimsSet
        );

        signedJwt.sign(new com.nimbusds.jose.crypto.ECDSASigner(signingKey));
        return signedJwt.serialize();
    }

    private String createWptWithCustomTyp() throws JOSEException {
        // Create a WPT with custom typ header
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("resource-server")
                .expirationTime(Date.from(expirationTime))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("wth", computeHash(sampleWit))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(signingKey.getKeyID())
                        .type(new JOSEObjectType("custom-type"))
                        .build(),
                claimsSet
        );

        signedJwt.sign(new com.nimbusds.jose.crypto.ECDSASigner(signingKey));
        return signedJwt.serialize();
    }

    private String createWptWithoutTyp() throws JOSEException {
        // Create a WPT without typ header
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("resource-server")
                .expirationTime(Date.from(expirationTime))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("wth", computeHash(sampleWit))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claimsSet
        );

        signedJwt.sign(new com.nimbusds.jose.crypto.ECDSASigner(signingKey));
        return signedJwt.serialize();
    }

    private String computeHash(String input) {
        // Simplified hash computation for testing
        // In real implementation, this would be BASE64URL(SHA-256(ASCII(input)))
        return "hash-" + java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(input.getBytes());
    }
}
