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
package ai.shao.aap.rs.core.trust;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("TrustDomain Tests")
class TrustDomainTest {

    private static final String VALID_DOMAIN_ID = "example.com";

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create trust domain with valid domain ID")
        void shouldCreateTrustDomainWithValidDomainId() {
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            assertThat(domain).isNotNull();
            assertThat(domain.domainId()).isEqualTo(VALID_DOMAIN_ID);
        }

        @Test
        @DisplayName("Should throw exception when domain ID is null")
        void shouldThrowExceptionWhenDomainIdIsNull() {
            assertThatThrownBy(() -> new TrustDomain(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Domain ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when domain ID is empty")
        void shouldThrowExceptionWhenDomainIdIsEmpty() {
            assertThatThrownBy(() -> new TrustDomain(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Domain ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when domain ID is whitespace")
        void shouldThrowExceptionWhenDomainIdIsWhitespace() {
            assertThatThrownBy(() -> new TrustDomain("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Domain ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("equals and hashCode")
    class EqualityTests {

        @Test
        @DisplayName("Should be equal when domain IDs are same")
        void shouldBeEqualWhenDomainIdsAreSame() {
            TrustDomain domain1 = new TrustDomain(VALID_DOMAIN_ID);
            TrustDomain domain2 = new TrustDomain(VALID_DOMAIN_ID);

            assertThat(domain1).isEqualTo(domain2);
            assertThat(domain1.hashCode()).isEqualTo(domain2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when domain IDs are different")
        void shouldNotBeEqualWhenDomainIdsAreDifferent() {
            TrustDomain domain1 = new TrustDomain("example.com");
            TrustDomain domain2 = new TrustDomain("other.com");

            assertThat(domain1).isNotEqualTo(domain2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            assertThat(domain).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            assertThat(domain).isNotEqualTo("string");
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            assertThat(domain).isEqualTo(domain);
        }
    }

    @Nested
    @DisplayName("toString")
    class ToStringTests {

        @Test
        @DisplayName("Should contain domain ID in toString")
        void shouldContainDomainIdInToString() {
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            String result = domain.toString();

            assertThat(result).contains(VALID_DOMAIN_ID);
        }
    }
}
