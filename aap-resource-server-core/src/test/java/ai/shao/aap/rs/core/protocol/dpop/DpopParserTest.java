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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.shao.aap.rs.core.model.token.DpopToken;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link DpopParser}. */
@DisplayName("DPoP Parser Tests")
class DpopParserTest {

    private DpopParser dpopParser;
    private OctetKeyPair signingKey;
    private String sampleWit;
    private String sampleAccessToken;

    @BeforeEach
    void setUp() throws JOSEException {
        dpopParser = new DpopParser();

        signingKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("dpop-signing-key").generate();

        sampleWit = "sample-ct-jwt-string";
        sampleAccessToken = "sample-access-token";
    }

    @Nested
    @DisplayName("parse() - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should parse valid DPoP successfully")
        void shouldParseValidWptSuccessfully() throws Exception {
            String wptJwt = createValidWpt();

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop).isNotNull();
            assertThat(dpop.claims()).isNotNull();
            assertThat(dpop.jwtString()).isNotNull();
            assertThat(dpop.signature()).isNotNull();
        }

        @Test
        @DisplayName("Should parse DPoP with all required claims")
        void shouldParseWptWithAllRequiredClaims() throws Exception {
            String wptJwt = createValidWpt();

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop.claims().audience()).isEqualTo("[resource-server]");
            assertThat(dpop.claims().jwtId()).isNotNull();
            assertThat(dpop.claims().workloadTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should parse DPoP with optional claims")
        void shouldParseWptWithOptionalClaims() throws Exception {
            String wptJwt = createWptWithOptionalClaims();

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop.claims().accessTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should reject DPoP with wrong typ header")
        void shouldRejectWptWithWrongTypHeader() throws Exception {
            String wptJwt = createWptWithCustomTyp();
            SignedJWT signedJwt = SignedJWT.parse(wptJwt);
            assertThatThrownBy(() -> dpopParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("typ header must be 'dpop+jwt'");
        }
    }

    @Nested
    @DisplayName("parse() - Input Validation")
    class InputValidationTests {

        @Test
        @DisplayName("Should throw exception when signed JWT is null")
        void shouldThrowExceptionWhenSignedJwtIsNull() {
            assertThatThrownBy(() -> dpopParser.parse((SignedJWT) null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Signed JWT");
        }

        @Test
        @DisplayName("Should throw exception when DPoP is malformed")
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

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop.claims().audience()).isEqualTo("[resource-server]");
        }

        @Test
        @DisplayName("Should parse expiration time claim correctly")
        void shouldParseExpirationTimeClaimCorrectly() throws Exception {
            String wptJwt = createValidWpt();

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop.claims().expirationTime()).isNotNull();
            assertThat(dpop.claims().expirationTime()).isAfter(Instant.now());
        }

        @Test
        @DisplayName("Should parse JWT ID claim correctly")
        void shouldParseJwtIdClaimCorrectly() throws Exception {
            String wptJwt = createValidWpt();

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop.claims().jwtId()).isNotNull();
        }

        @Test
        @DisplayName("Should parse workload token hash claim correctly")
        void shouldParseWorkloadTokenHashClaimCorrectly() throws Exception {
            String wptJwt = createValidWpt();

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop.claims().workloadTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should parse access token hash claim correctly")
        void shouldParseAccessTokenHashClaimCorrectly() throws Exception {
            String wptJwt = createWptWithOptionalClaims();

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop.claims().accessTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should handle null optional claims")
        void shouldHandleNullOptionalClaims() throws Exception {
            String wptJwt = createValidWpt();

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop.claims().accessTokenHash()).isNull();
        }
    }

    @Nested
    @DisplayName("parse() - Header Parsing")
    class HeaderParsingTests {

        @Test
        @DisplayName("Should reject DPoP without typ header")
        void shouldRejectWptWithoutTypHeader() throws Exception {
            String wptJwt = createWptWithoutTyp();
            SignedJWT signedJwt = SignedJWT.parse(wptJwt);
            assertThatThrownBy(() -> dpopParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("typ header must be 'dpop+jwt'");
        }

        @Test
        @DisplayName("Should reject DPoP signed with non-EdDSA algorithm")
        void shouldRejectWptSignedWithNonEdDsaAlgorithm() throws Exception {
            RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("rs-key").generate();
            JWTClaimsSet claims =
                    new JWTClaimsSet.Builder()
                            .audience("resource-server")
                            .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                            .jwtID(java.util.UUID.randomUUID().toString())
                            .claim("wth", computeHash(sampleWit))
                            .build();
            SignedJWT rsaSigned =
                    new SignedJWT(
                            new JWSHeader.Builder(JWSAlgorithm.RS256)
                                    .keyID(rsaKey.getKeyID())
                                    .type(new JOSEObjectType("dpop+jwt"))
                                    .build(),
                            claims);
            rsaSigned.sign(new RSASSASigner(rsaKey));

            SignedJWT signedJwt = SignedJWT.parse(rsaSigned.serialize());
            assertThatThrownBy(() -> dpopParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("alg header must be 'EdDSA'");
        }

        @Test
        @DisplayName("Should reject DPoP with disallowed JOSE header parameter (kid)")
        void shouldRejectWptWithKidHeader() throws Exception {
            JWTClaimsSet claims =
                    new JWTClaimsSet.Builder()
                            .audience("resource-server")
                            .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                            .jwtID(java.util.UUID.randomUUID().toString())
                            .claim("wth", computeHash(sampleWit))
                            .build();
            SignedJWT signedJwt =
                    new SignedJWT(
                            new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                                    .keyID(signingKey.getKeyID())
                                    .type(new JOSEObjectType("dpop+jwt"))
                                    .build(),
                            claims);
            signedJwt.sign(new com.nimbusds.jose.crypto.Ed25519Signer(signingKey));

            SignedJWT parsed = SignedJWT.parse(signedJwt.serialize());
            assertThatThrownBy(() -> dpopParser.parse(parsed))
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

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop.jwtString()).isEqualTo(wptJwt);
        }

        @Test
        @DisplayName("Should extract signature correctly")
        void shouldExtractSignatureCorrectly() throws Exception {
            String wptJwt = createValidWpt();

            DpopToken dpop = dpopParser.parse(SignedJWT.parse(wptJwt));

            assertThat(dpop.signature()).isNotNull();
            String[] parts = wptJwt.split("\\.");
            assertThat(parts).hasSize(3);
            assertThat(dpop.signature()).isEqualTo(parts[2]);
        }
    }

    private String createValidWpt() throws JOSEException {
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .audience("resource-server")
                        .expirationTime(Date.from(expirationTime))
                        .jwtID(java.util.UUID.randomUUID().toString())
                        .claim("wth", computeHash(sampleWit))
                        .build();

        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                                .type(new JOSEObjectType("dpop+jwt"))
                                .build(),
                        claimsSet);

        signedJwt.sign(new Ed25519Signer(signingKey));
        return signedJwt.serialize();
    }

    private String createWptWithOptionalClaims() throws JOSEException {
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .audience("resource-server")
                        .expirationTime(Date.from(expirationTime))
                        .jwtID(java.util.UUID.randomUUID().toString())
                        .claim("wth", computeHash(sampleWit))
                        .claim("ath", computeHash(sampleAccessToken))
                        .build();

        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                                .type(new JOSEObjectType("dpop+jwt"))
                                .build(),
                        claimsSet);

        signedJwt.sign(new Ed25519Signer(signingKey));
        return signedJwt.serialize();
    }

    private String createWptWithCustomTyp() throws JOSEException {
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .audience("resource-server")
                        .expirationTime(Date.from(expirationTime))
                        .jwtID(java.util.UUID.randomUUID().toString())
                        .claim("wth", computeHash(sampleWit))
                        .build();

        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                                .keyID(signingKey.getKeyID())
                                .type(new JOSEObjectType("custom-type"))
                                .build(),
                        claimsSet);

        signedJwt.sign(new Ed25519Signer(signingKey));
        return signedJwt.serialize();
    }

    private String createWptWithoutTyp() throws JOSEException {
        Instant expirationTime = Instant.now().plusSeconds(3600);

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .audience("resource-server")
                        .expirationTime(Date.from(expirationTime))
                        .jwtID(java.util.UUID.randomUUID().toString())
                        .claim("wth", computeHash(sampleWit))
                        .build();

        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                                .keyID(signingKey.getKeyID())
                                .build(),
                        claimsSet);

        signedJwt.sign(new Ed25519Signer(signingKey));
        return signedJwt.serialize();
    }

    private String computeHash(String input) {
        return "hash-"
                + java.util.Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(input.getBytes());
    }
}
