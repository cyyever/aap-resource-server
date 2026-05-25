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
package ai.shao.aap.rs.core.model.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.shao.aap.rs.core.model.jwk.Jwk;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link CredentialToken}. */
@DisplayName("CredentialToken Tests")
class CredentialTokenTest {

    private Instant futureExpirationTime;
    private Instant pastExpirationTime;
    private Jwk testJwk;
    private CredentialToken.Claims.Confirmation testConfirmation;
    private CredentialToken.Claims validClaims;

    @BeforeEach
    void setUp() {
        futureExpirationTime = Instant.ofEpochMilli(System.currentTimeMillis() + 3600000);
        pastExpirationTime = Instant.ofEpochMilli(System.currentTimeMillis() - 3600000);

        testJwk = Jwk.builder().x("test_x_value").build();

        testConfirmation = CredentialToken.Claims.Confirmation.builder().jwk(testJwk).build();

        validClaims =
                CredentialToken.Claims.builder()
                        .issuer("https://idp.example.com")
                        .subject("agent-my-workload")
                        .expirationTime(futureExpirationTime)
                        .jwtId("test-jti-123")
                        .confirmation(testConfirmation)
                        .build();
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build token with all fields")
        void shouldBuildTokenWithAllFields() {
            CredentialToken token =
                    CredentialToken.builder()
                            .claims(validClaims)
                            .signature("test-signature")
                            .jwtString("test.jwt.string")
                            .build();

            assertThat(token).isNotNull();
            assertThat(token.claims()).isEqualTo(validClaims);
            assertThat(token.signature()).isEqualTo("test-signature");
            assertThat(token.jwtString()).isEqualTo("test.jwt.string");
        }

        @Test
        @DisplayName("Should build token with minimal required fields")
        void shouldBuildTokenWithMinimalRequiredFields() {
            CredentialToken token = CredentialToken.builder().claims(validClaims).build();

            assertThat(token).isNotNull();
            assertThat(token.claims()).isEqualTo(validClaims);
            assertThat(token.signature()).isNull();
            assertThat(token.jwtString()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when building with null claims")
        void shouldThrowExceptionWhenBuildingWithNullClaims() {
            assertThatThrownBy(() -> CredentialToken.builder().claims(null).build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("claims is REQUIRED for CT");
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should return true for expired token")
        void shouldReturnTrueForExpiredToken() {
            CredentialToken.Claims expiredClaims =
                    CredentialToken.Claims.builder()
                            .issuer("https://idp.example.com")
                            .subject("agent-expired")
                            .expirationTime(pastExpirationTime)
                            .confirmation(testConfirmation)
                            .build();

            CredentialToken token = CredentialToken.builder().claims(expiredClaims).build();

            assertThat(token.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should return true for valid token")
        void shouldReturnTrueForValidToken() {
            CredentialToken token = CredentialToken.builder().claims(validClaims).build();

            assertThat(token.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should return false for expired token in isValid")
        void shouldReturnFalseForExpiredTokenInIsValid() {
            CredentialToken.Claims expiredClaims =
                    CredentialToken.Claims.builder()
                            .issuer("https://idp.example.com")
                            .subject("agent-expired")
                            .expirationTime(pastExpirationTime)
                            .confirmation(testConfirmation)
                            .build();

            CredentialToken token = CredentialToken.builder().claims(expiredClaims).build();

            assertThat(token.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should return false when not expired")
        void shouldReturnFalseWhenNotExpired() {
            CredentialToken token = CredentialToken.builder().claims(validClaims).build();

            assertThat(token.isExpired()).isFalse();
        }
    }

    @Nested
    @DisplayName("Claims Tests")
    class ClaimsTests {

        @Test
        @DisplayName("Should build claims with all fields")
        void shouldBuildClaimsWithAllFields() {
            CredentialToken.Claims.Confirmation confirmation =
                    CredentialToken.Claims.Confirmation.builder().jwk(testJwk).build();

            CredentialToken.Claims claims =
                    CredentialToken.Claims.builder()
                            .issuer("https://idp.example.com")
                            .subject("agent-test")
                            .expirationTime(futureExpirationTime)
                            .jwtId("test-jti")
                            .confirmation(confirmation)
                            .build();

            assertThat(claims.issuer()).isEqualTo("https://idp.example.com");
            assertThat(claims.subject()).isEqualTo("agent-test");
            assertThat(claims.expirationTime()).isEqualTo(futureExpirationTime);
            assertThat(claims.jwtId()).isEqualTo("test-jti");
            assertThat(claims.confirmation()).isEqualTo(confirmation);
            assertThat(claims.jwk()).isEqualTo(testJwk);
        }

        @Test
        @DisplayName("Should build claims with minimal required fields")
        void shouldBuildClaimsWithMinimalRequiredFields() {
            CredentialToken.Claims.Confirmation confirmation =
                    CredentialToken.Claims.Confirmation.builder().jwk(testJwk).build();
            CredentialToken.Claims claims =
                    CredentialToken.Claims.builder()
                            .subject("agent-test")
                            .expirationTime(futureExpirationTime)
                            .confirmation(confirmation)
                            .build();

            assertThat(claims.issuer()).isNull();
            assertThat(claims.subject()).isEqualTo("agent-test");
            assertThat(claims.expirationTime()).isEqualTo(futureExpirationTime);
            assertThat(claims.jwtId()).isNull();
            assertThat(claims.confirmation()).isEqualTo(confirmation);
        }

        @Test
        @DisplayName("Should throw exception when building claims with null subject")
        void shouldThrowExceptionWhenBuildingClaimsWithNullSubject() {
            CredentialToken.Claims.Confirmation confirmation =
                    CredentialToken.Claims.Confirmation.builder().jwk(testJwk).build();
            assertThatThrownBy(
                            () ->
                                    CredentialToken.Claims.builder()
                                            .subject(null)
                                            .expirationTime(futureExpirationTime)
                                            .confirmation(confirmation)
                                            .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("subject (sub) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when building claims with null confirmation")
        void shouldThrowExceptionWhenBuildingClaimsWithNullConfirmation() {
            assertThatThrownBy(
                            () ->
                                    CredentialToken.Claims.builder()
                                            .subject("agent-test")
                                            .expirationTime(futureExpirationTime)
                                            .confirmation(null)
                                            .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("confirmation (cnf) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when building claims with empty subject")
        void shouldThrowExceptionWhenBuildingClaimsWithEmptySubject() {
            assertThatThrownBy(
                            () ->
                                    CredentialToken.Claims.builder()
                                            .subject("")
                                            .expirationTime(futureExpirationTime)
                                            .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("subject (sub) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when building claims with null expiration time")
        void shouldThrowExceptionWhenBuildingClaimsWithNullExpirationTime() {
            assertThatThrownBy(
                            () ->
                                    CredentialToken.Claims.builder()
                                            .subject("agent-test")
                                            .expirationTime(null)
                                            .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("expirationTime (exp) is REQUIRED");
        }

        @Test
        @DisplayName("Should check if claims are expired")
        void shouldCheckIfClaimsAreExpired() {
            CredentialToken.Claims expiredClaims =
                    CredentialToken.Claims.builder()
                            .subject("agent-expired")
                            .expirationTime(pastExpirationTime)
                            .confirmation(testConfirmation)
                            .build();

            assertThat(expiredClaims.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should return workload identifier")
        void shouldReturnWorkloadIdentifier() {
            assertThat(validClaims.getWorkloadIdentifier()).isEqualTo("agent-my-workload");
        }
    }

    @Nested
    @DisplayName("Confirmation Tests")
    class ConfirmationTests {

        @Test
        @DisplayName("Should build confirmation with JWK")
        void shouldBuildConfirmationWithJwk() {
            CredentialToken.Claims.Confirmation confirmation =
                    CredentialToken.Claims.Confirmation.builder().jwk(testJwk).build();

            assertThat(confirmation.jwk()).isEqualTo(testJwk);
        }

        @Test
        @DisplayName("Should throw exception when building confirmation with null JWK")
        void shouldThrowExceptionWhenBuildingConfirmationWithNullJwk() {
            assertThatThrownBy(
                            () -> CredentialToken.Claims.Confirmation.builder().jwk(null).build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("jwk is REQUIRED in confirmation (cnf) claim");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty signature")
        void shouldHandleEmptySignature() {
            CredentialToken token =
                    CredentialToken.builder().claims(validClaims).signature("").build();

            assertThat(token.signature()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty jwtString")
        void shouldHandleEmptyJwtString() {
            CredentialToken token =
                    CredentialToken.builder().claims(validClaims).jwtString("").build();

            assertThat(token.jwtString()).isEqualTo("");
        }

        @Test
        @DisplayName("Should preserve URI-shaped subject verbatim")
        void shouldPreserveUriShapedSubject() {
            CredentialToken.Claims claims =
                    CredentialToken.Claims.builder()
                            .subject("agent-my-service")
                            .expirationTime(futureExpirationTime)
                            .confirmation(testConfirmation)
                            .build();

            CredentialToken token = CredentialToken.builder().claims(claims).build();

            assertThat(token.getSubject()).isEqualTo("agent-my-service");
        }
    }
}
