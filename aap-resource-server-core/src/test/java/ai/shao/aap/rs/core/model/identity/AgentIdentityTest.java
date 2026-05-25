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
package ai.shao.aap.rs.core.model.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AgentIdentity}.
 *
 * <p>Tests the Agent Identity model's behavior including:
 *
 * <ul>
 *   <li>Building identities with all required and optional fields
 *   <li>Getter methods for all properties
 *   <li>Equals, hashCode, and toString methods
 *   <li>Builder pattern with validation
 *   <li>IssuedFor inner class
 *   <li>Default version behavior
 * </ul>
 *
 * @since 1.0
 */
@DisplayName("AgentIdentity Tests")
class AgentIdentityTest {

    private static final String VERSION = "1.0";
    private static final String AGENT_ID = "agent-123";
    private static final String ISSUER = "https://issuer.example.com";
    private static final String ISSUED_TO = "https://issued-to.example.com|user-123";
    private static final Instant NOW = Instant.now();

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build identity with all fields")
        void shouldBuildIdentityWithAllFields() {
            // Given
            AgentIdentity.IssuedFor issuedFor =
                    AgentIdentity.IssuedFor.builder()
                            .platform("cloud-platform")
                            .client("web-app")
                            .clientInstance("instance-1")
                            .build();

            // When
            AgentIdentity identity =
                    AgentIdentity.builder()
                            .version(VERSION)
                            .id(AGENT_ID)
                            .issuer(ISSUER)
                            .issuedTo(ISSUED_TO)
                            .issuedFor(issuedFor)
                            .issuanceDate(NOW)
                            .validFrom(NOW)
                            .expires(NOW.plusSeconds(3600))
                            .build();

            // Then
            assertThat(identity).isNotNull();
            assertThat(identity.version()).isEqualTo(VERSION);
            assertThat(identity.id()).isEqualTo(AGENT_ID);
            assertThat(identity.issuer()).isEqualTo(ISSUER);
            assertThat(identity.issuedTo()).isEqualTo(ISSUED_TO);
            assertThat(identity.issuedFor()).isNotNull();
            assertThat(identity.issuedFor().platform()).isEqualTo("cloud-platform");
            assertThat(identity.issuedFor().client()).isEqualTo("web-app");
            assertThat(identity.issuedFor().clientInstance()).isEqualTo("instance-1");
            assertThat(identity.issuanceDate()).isEqualTo(NOW);
            assertThat(identity.validFrom()).isEqualTo(NOW);
            assertThat(identity.expires()).isEqualTo(NOW.plusSeconds(3600));
        }

        @Test
        @DisplayName("Should build identity with default version")
        void shouldBuildIdentityWithDefaultVersion() {
            // When
            AgentIdentity identity =
                    AgentIdentity.builder().id(AGENT_ID).issuer(ISSUER).issuedTo(ISSUED_TO).build();

            // Then
            assertThat(identity.version()).isEqualTo("1.0");
        }

        @Test
        @DisplayName("Should build identity with null optional fields")
        void shouldBuildIdentityWithNullOptionalFields() {
            // When
            AgentIdentity identity =
                    AgentIdentity.builder().id(AGENT_ID).issuer(ISSUER).issuedTo(ISSUED_TO).build();

            // Then
            assertThat(identity.issuedFor()).isNull();
            assertThat(identity.issuanceDate()).isNull();
            assertThat(identity.validFrom()).isNull();
            assertThat(identity.expires()).isNull();
        }
    }

    @Nested
    @DisplayName("IssuedFor Tests")
    class IssuedForTests {

        @Test
        @DisplayName("Should build IssuedFor with all fields")
        void shouldBuildIssuedForWithAllFields() {
            // When
            AgentIdentity.IssuedFor issuedFor =
                    AgentIdentity.IssuedFor.builder()
                            .platform("platform-1")
                            .client("client-1")
                            .clientInstance("instance-1")
                            .build();

            // Then
            assertThat(issuedFor.platform()).isEqualTo("platform-1");
            assertThat(issuedFor.client()).isEqualTo("client-1");
            assertThat(issuedFor.clientInstance()).isEqualTo("instance-1");
        }

        @Test
        @DisplayName("Should build IssuedFor with null fields")
        void shouldBuildIssuedForWithNullFields() {
            // When
            AgentIdentity.IssuedFor issuedFor = AgentIdentity.IssuedFor.builder().build();

            // Then
            assertThat(issuedFor.platform()).isNull();
            assertThat(issuedFor.client()).isNull();
            assertThat(issuedFor.clientInstance()).isNull();
        }

        @Test
        @DisplayName("IssuedFor should be equal when all fields match")
        void issuedForShouldBeEqualWhenAllFieldsMatch() {
            // Given
            AgentIdentity.IssuedFor issuedFor1 =
                    AgentIdentity.IssuedFor.builder()
                            .platform("platform-1")
                            .client("client-1")
                            .clientInstance("instance-1")
                            .build();
            AgentIdentity.IssuedFor issuedFor2 =
                    AgentIdentity.IssuedFor.builder()
                            .platform("platform-1")
                            .client("client-1")
                            .clientInstance("instance-1")
                            .build();

            // When & Then
            assertThat(issuedFor1).isEqualTo(issuedFor2);
            assertThat(issuedFor1.hashCode()).isEqualTo(issuedFor2.hashCode());
        }

        @Test
        @DisplayName("IssuedFor should have correct toString")
        void issuedForShouldHaveCorrectToString() {
            // Given
            AgentIdentity.IssuedFor issuedFor =
                    AgentIdentity.IssuedFor.builder()
                            .platform("platform-1")
                            .client("client-1")
                            .clientInstance("instance-1")
                            .build();

            // When
            String toString = issuedFor.toString();

            // Then
            assertThat(toString).contains("IssuedFor");
            assertThat(toString).contains("platform=platform-1");
            assertThat(toString).contains("client=client-1");
            assertThat(toString).contains("clientInstance=instance-1");
        }
    }

    /**
     * Helper method to create a test AgentIdentity instance.
     *
     * @return a test AgentIdentity instance
     */
    private AgentIdentity createTestIdentity() {
        AgentIdentity.IssuedFor issuedFor =
                AgentIdentity.IssuedFor.builder()
                        .platform("cloud-platform")
                        .client("web-app")
                        .clientInstance("instance-1")
                        .build();

        return AgentIdentity.builder()
                .version(VERSION)
                .id(AGENT_ID)
                .issuer(ISSUER)
                .issuedTo(ISSUED_TO)
                .issuedFor(issuedFor)
                .issuanceDate(NOW)
                .validFrom(NOW)
                .expires(NOW.plusSeconds(3600))
                .build();
    }
}
