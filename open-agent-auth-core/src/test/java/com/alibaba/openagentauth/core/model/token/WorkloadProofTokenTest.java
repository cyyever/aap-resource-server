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
package com.alibaba.openagentauth.core.model.token;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WorkloadProofToken}.
 * <p>
 * Tests the Workload Proof Token (WPT) model's behavior including:
 * <ul>
 *   <li>Building tokens with all required and optional fields</li>
 *   <li>Getter methods for header, claims, and signature</li>
 *   <li>Token validation (isExpired, isValid)</li>
 *   <li>Builder pattern with validation</li>
 *   <li>Header and Claims inner classes</li>
 *   <li>Token hash handling (wth, ath, tth, oth)</li>
 *   <li>equals, hashCode, and toString methods</li>
 *   <li>Error handling for missing required fields</li>
 * </ul>
 * </p>
 */
@DisplayName("WorkloadProofToken Tests")
class WorkloadProofTokenTest {

    private Date futureExpirationTime;
    private Date pastExpirationTime;
    private WorkloadProofToken.Header validHeader;
    private WorkloadProofToken.Claims validClaims;

    @BeforeEach
    void setUp() {
        // Set up test dates
        futureExpirationTime = new Date(System.currentTimeMillis() + 3600000); // 1 hour from now
        pastExpirationTime = new Date(System.currentTimeMillis() - 3600000); // 1 hour ago

        // Set up valid header
        validHeader = WorkloadProofToken.Header.builder()
                .type(WorkloadProofToken.Header.MEDIA_TYPE)
                .algorithm("ES256")
                .build();

        // Set up valid claims
        validClaims = WorkloadProofToken.Claims.builder()
                .audience("https://resource-server.example.com")
                .expirationTime(futureExpirationTime)
                .jwtId("test-jti-456")
                .workloadTokenHash("abc123def456")
                .accessTokenHash("xyz789uvw012")
                .build();
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build token with all fields")
        void shouldBuildTokenWithAllFields() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("test-signature")
                    .jwtString("test.jwt.string")
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.header()).isEqualTo(validHeader);
            assertThat(token.claims()).isEqualTo(validClaims);
            assertThat(token.signature()).isEqualTo("test-signature");
            assertThat(token.jwtString()).isEqualTo("test.jwt.string");
        }

        @Test
        @DisplayName("Should build token with minimal required fields")
        void shouldBuildTokenWithMinimalRequiredFields() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.header()).isEqualTo(validHeader);
            assertThat(token.claims()).isEqualTo(validClaims);
            assertThat(token.signature()).isNull();
            assertThat(token.jwtString()).isNull();
        }

        @Test
        @DisplayName("Should build token with only signature")
        void shouldBuildTokenWithOnlySignature() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("signature-only")
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.signature()).isEqualTo("signature-only");
            assertThat(token.jwtString()).isNull();
        }

        @Test
        @DisplayName("Should build token with only jwtString")
        void shouldBuildTokenWithOnlyJwtString() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .jwtString("jwt-string-only")
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.signature()).isNull();
            assertThat(token.jwtString()).isEqualTo("jwt-string-only");
        }

        @Test
        @DisplayName("Should throw exception when building with null header")
        void shouldThrowExceptionWhenBuildingWithNullHeader() {
            assertThatThrownBy(() -> WorkloadProofToken.builder()
                    .header(null)
                    .claims(validClaims)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("header is REQUIRED for WPT");
        }

        @Test
        @DisplayName("Should throw exception when building with null claims")
        void shouldThrowExceptionWhenBuildingWithNullClaims() {
            assertThatThrownBy(() -> WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("claims is REQUIRED for WPT");
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should return false for expired token")
        void shouldReturnFalseForExpiredToken() {
            WorkloadProofToken.Claims expiredClaims = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(pastExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(expiredClaims)
                    .build();

            assertThat(token.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should return true for valid token")
        void shouldReturnTrueForValidToken() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should return false for expired token in isValid")
        void shouldReturnFalseForExpiredTokenInIsValid() {
            WorkloadProofToken.Claims expiredClaims = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(pastExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(expiredClaims)
                    .build();

            assertThat(token.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should return false when not expired")
        void shouldReturnFalseWhenNotExpired() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.isExpired()).isFalse();
        }

        @Test
        @DisplayName("Should return true for valid token without expiration time")
        void shouldReturnTrueForValidTokenWithoutExpirationTime() {
            WorkloadProofToken.Claims claimsWithoutExpiration = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claimsWithoutExpiration)
                    .build();

            assertThat(token.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("Header Tests")
    class HeaderTests {

        @Test
        @DisplayName("Should build header with all fields")
        void shouldBuildHeaderWithAllFields() {
            WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            assertThat(header.type()).isEqualTo(WorkloadProofToken.Header.MEDIA_TYPE);
            assertThat(header.algorithm()).isEqualTo("ES256");
        }

        @Test
        @DisplayName("Should build header with default type")
        void shouldBuildHeaderWithDefaultType() {
            WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                    .algorithm("RS256")
                    .build();

            assertThat(header.type()).isEqualTo(WorkloadProofToken.Header.MEDIA_TYPE);
            assertThat(header.algorithm()).isEqualTo("RS256");
        }

        @Test
        @DisplayName("Should throw exception when building header with null type")
        void shouldThrowExceptionWhenBuildingHeaderWithNullType() {
            assertThatThrownBy(() -> WorkloadProofToken.Header.builder()
                    .type(null)
                    .algorithm("ES256")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("type (typ) is REQUIRED and should be 'wpt+jwt'");
        }

        @Test
        @DisplayName("Should throw exception when building header with empty type")
        void shouldThrowExceptionWhenBuildingHeaderWithEmptyType() {
            assertThatThrownBy(() -> WorkloadProofToken.Header.builder()
                    .type("")
                    .algorithm("ES256")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("type (typ) is REQUIRED and should be 'wpt+jwt'");
        }

        @Test
        @DisplayName("Should throw exception when building header with null algorithm")
        void shouldThrowExceptionWhenBuildingHeaderWithNullAlgorithm() {
            assertThatThrownBy(() -> WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("algorithm (alg) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when building header with empty algorithm")
        void shouldThrowExceptionWhenBuildingHeaderWithEmptyAlgorithm() {
            assertThatThrownBy(() -> WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("algorithm (alg) is REQUIRED");
        }

        @Test
        @DisplayName("Should implement equals correctly for header")
        void shouldImplementEqualsCorrectlyForHeader() {
            WorkloadProofToken.Header header1 = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            WorkloadProofToken.Header header2 = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            WorkloadProofToken.Header header3 = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("RS256")
                    .build();

            assertThat(header1).isEqualTo(header2);
            assertThat(header1).isNotEqualTo(header3);
            assertThat(header1).isNotEqualTo(null);
            assertThat(header1).isNotEqualTo("string");
        }

        @Test
        @DisplayName("Should implement hashCode correctly for header")
        void shouldImplementHashCodeCorrectlyForHeader() {
            WorkloadProofToken.Header header1 = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            WorkloadProofToken.Header header2 = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            assertThat(header1.hashCode()).isEqualTo(header2.hashCode());
        }

        @Test
        @DisplayName("Should implement toString for header")
        void shouldImplementToStringForHeader() {
            WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                    .type(WorkloadProofToken.Header.MEDIA_TYPE)
                    .algorithm("ES256")
                    .build();

            String toString = header.toString();
            assertThat(toString).contains("wpt+jwt");
            assertThat(toString).contains("ES256");
        }
    }

    @Nested
    @DisplayName("Claims Tests")
    class ClaimsTests {

        @Test
        @DisplayName("Should build claims with all fields")
        void shouldBuildClaimsWithAllFields() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .jwtId("test-jti")
                    .workloadTokenHash("abc123")
                    .accessTokenHash("xyz789")
                    .build();

            assertThat(claims.audience()).isEqualTo("https://resource-server.example.com");
            assertThat(claims.expirationTime()).isEqualTo(futureExpirationTime);
            assertThat(claims.jwtId()).isEqualTo("test-jti");
            assertThat(claims.workloadTokenHash()).isEqualTo("abc123");
            assertThat(claims.accessTokenHash()).isEqualTo("xyz789");
        }

        @Test
        @DisplayName("Should build claims with minimal required fields")
        void shouldBuildClaimsWithMinimalRequiredFields() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(claims.audience()).isNull();
            assertThat(claims.expirationTime()).isNull();
            assertThat(claims.jwtId()).isNull();
            assertThat(claims.workloadTokenHash()).isEqualTo("abc123");
            assertThat(claims.accessTokenHash()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when building claims with null workload token hash")
        void shouldThrowExceptionWhenBuildingClaimsWithNullWorkloadTokenHash() {
            assertThatThrownBy(() -> WorkloadProofToken.Claims.builder()
                    .workloadTokenHash(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("workloadTokenHash (wth) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when building claims with empty workload token hash")
        void shouldThrowExceptionWhenBuildingClaimsWithEmptyWorkloadTokenHash() {
            assertThatThrownBy(() -> WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("workloadTokenHash (wth) is REQUIRED");
        }

        @Test
        @DisplayName("Should check if claims are expired")
        void shouldCheckIfClaimsAreExpired() {
            WorkloadProofToken.Claims expiredClaims = WorkloadProofToken.Claims.builder()
                    .expirationTime(pastExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(expiredClaims.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should check if claims are not expired")
        void shouldCheckIfClaimsAreNotExpired() {
            assertThat(validClaims.isExpired()).isFalse();
        }

        @Test
        @DisplayName("Should check if claims are valid")
        void shouldCheckIfClaimsAreValid() {
            assertThat(validClaims.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should check if claims are invalid when expired")
        void shouldCheckIfClaimsAreInvalidWhenExpired() {
            WorkloadProofToken.Claims expiredClaims = WorkloadProofToken.Claims.builder()
                    .expirationTime(pastExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(expiredClaims.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should return true for valid claims without expiration time")
        void shouldReturnTrueForValidClaimsWithoutExpirationTime() {
            WorkloadProofToken.Claims claimsWithoutExpiration = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(claimsWithoutExpiration.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should implement equals correctly for claims")
        void shouldImplementEqualsCorrectlyForClaims() {
            WorkloadProofToken.Claims claims1 = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken.Claims claims2 = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken.Claims claims3 = WorkloadProofToken.Claims.builder()
                    .audience("https://other-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(claims1).isEqualTo(claims2);
            assertThat(claims1).isNotEqualTo(claims3);
        }

        @Test
        @DisplayName("Should implement hashCode correctly for claims")
        void shouldImplementHashCodeCorrectlyForClaims() {
            WorkloadProofToken.Claims claims1 = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken.Claims claims2 = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(claims1.hashCode()).isEqualTo(claims2.hashCode());
        }

        @Test
        @DisplayName("Should implement toString for claims")
        void shouldImplementToStringForClaims() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            String toString = claims.toString();
            assertThat(toString).contains("Claims");
            assertThat(toString).contains("workloadTokenHash");
        }
    }

    @Nested
    @DisplayName("Token Hash Tests")
    class TokenHashTests {

        @Test
        @DisplayName("Should handle workload token hash")
        void shouldHandleWorkloadTokenHash() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("wit-hash-123")
                    .build();

            assertThat(claims.workloadTokenHash()).isEqualTo("wit-hash-123");
        }

        @Test
        @DisplayName("Should handle access token hash")
        void shouldHandleAccessTokenHash() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("wit-hash")
                    .accessTokenHash("at-hash-456")
                    .build();

            assertThat(claims.accessTokenHash()).isEqualTo("at-hash-456");
        }

        @Test
        @DisplayName("Should handle all token hash combinations")
        void shouldHandleAllTokenHashCombinations() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience("https://example.com")
                    .expirationTime(futureExpirationTime)
                    .jwtId("jti-123")
                    .workloadTokenHash("wit-hash")
                    .accessTokenHash("at-hash")
                    .build();

            assertThat(claims.workloadTokenHash()).isEqualTo("wit-hash");
            assertThat(claims.accessTokenHash()).isEqualTo("at-hash");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty audience")
        void shouldHandleEmptyAudience() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience("")
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getAudience()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty JWT ID")
        void shouldHandleEmptyJwtId() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .jwtId("")
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getJwtId()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty signature")
        void shouldHandleEmptySignature() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("")
                    .build();

            assertThat(token.signature()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty jwtString")
        void shouldHandleEmptyJwtString() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .jwtString("")
                    .build();

            assertThat(token.jwtString()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle single character workload token hash")
        void shouldHandleSingleCharacterWorkloadTokenHash() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("a")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getWorkloadTokenHash()).isEqualTo("a");
        }

        @Test
        @DisplayName("Should handle long workload token hash")
        void shouldHandleLongWorkloadTokenHash() {
            String longHash = "a".repeat(1000);
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash(longHash)
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getWorkloadTokenHash()).isEqualTo(longHash);
        }

        @Test
        @DisplayName("Should handle claims with only required field")
        void shouldHandleClaimsWithOnlyRequiredField() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("required-only")
                    .build();

            assertThat(claims.workloadTokenHash()).isEqualTo("required-only");
            assertThat(claims.audience()).isNull();
            assertThat(claims.expirationTime()).isNull();
            assertThat(claims.jwtId()).isNull();
            assertThat(claims.accessTokenHash()).isNull();
        }
    }
}
