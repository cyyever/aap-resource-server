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
package ai.shao.aap.rs.core.server.model.request;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("ResourceRequest Tests")
class ResourceRequestTest {

    private static ResourceRequest.Builder validBuilder() {
        return ResourceRequest.builder().ct("ct-token").dpop("dpop-token");
    }

    @Nested
    @DisplayName("Compact ctor invariants")
    class CompactCtorInvariants {

        @Test
        @DisplayName("Should throw when ct is null")
        void shouldThrowWhenCtNull() {
            assertThatThrownBy(() -> ResourceRequest.builder().dpop("dpop-token").build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("ct is REQUIRED");
        }

        @Test
        @DisplayName("Should throw when ct is empty")
        void shouldThrowWhenCtEmpty() {
            assertThatThrownBy(() -> ResourceRequest.builder().ct("").dpop("dpop-token").build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("ct is REQUIRED");
        }

        @Test
        @DisplayName("Should throw when dpop is null")
        void shouldThrowWhenDpopNull() {
            assertThatThrownBy(() -> ResourceRequest.builder().ct("ct-token").build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("dpop is REQUIRED");
        }

        @Test
        @DisplayName("Should throw when dpop is empty")
        void shouldThrowWhenDpopEmpty() {
            assertThatThrownBy(() -> ResourceRequest.builder().ct("ct-token").dpop("").build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("dpop is REQUIRED");
        }
    }

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build request with ct and dpop")
        void shouldBuildRequestWithCtAndDpop() {
            ResourceRequest request = validBuilder().build();

            assertThat(request.getCt()).isEqualTo("ct-token");
            assertThat(request.getDpop()).isEqualTo("dpop-token");
        }

        @Test
        @DisplayName("Should build request with HTTP information")
        void shouldBuildRequestWithHttpInformation() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");

            ResourceRequest request =
                    validBuilder()
                            .httpMethod("POST")
                            .httpUri("/api/resource")
                            .httpHeaders(headers)
                            .httpBody("{\"key\":\"value\"}")
                            .build();

            assertThat(request.getHttpMethod()).isEqualTo("POST");
            assertThat(request.getHttpUri()).isEqualTo("/api/resource");
            assertThat(request.getHttpHeaders()).hasSize(1);
            assertThat(request.getHttpBody()).isEqualTo("{\"key\":\"value\"}");
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            ResourceRequest request =
                    validBuilder().httpMethod("POST").httpUri("/api/resource").build();

            assertThat(request).isNotNull();
        }

        @Test
        @DisplayName("Should accept null values for optional HTTP fields")
        void shouldAcceptNullValuesForOptionalHttpFields() {
            ResourceRequest request =
                    validBuilder()
                            .httpMethod(null)
                            .httpUri(null)
                            .httpHeaders(null)
                            .httpBody(null)
                            .build();

            assertThat(request.getCt()).isEqualTo("ct-token");
            assertThat(request.getDpop()).isEqualTo("dpop-token");
            assertThat(request.getHttpMethod()).isNull();
            assertThat(request.getHttpUri()).isNull();
            assertThat(request.getHttpHeaders()).isNull();
            assertThat(request.getHttpBody()).isNull();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return ct")
        void shouldReturnCt() {
            assertThat(validBuilder().build().getCt()).isEqualTo("ct-token");
        }

        @Test
        @DisplayName("Should return dpop")
        void shouldReturnDpop() {
            assertThat(validBuilder().build().getDpop()).isEqualTo("dpop-token");
        }

        @Test
        @DisplayName("Should return httpMethod")
        void shouldReturnHttpMethod() {
            assertThat(validBuilder().httpMethod("POST").build().getHttpMethod()).isEqualTo("POST");
        }

        @Test
        @DisplayName("Should return httpUri")
        void shouldReturnHttpUri() {
            assertThat(validBuilder().httpUri("/api/resource").build().getHttpUri())
                    .isEqualTo("/api/resource");
        }

        @Test
        @DisplayName("Should return httpHeaders")
        void shouldReturnHttpHeaders() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");

            ResourceRequest request = validBuilder().httpHeaders(headers).build();

            assertThat(request.getHttpHeaders()).hasSize(1);
            assertThat(request.getHttpHeaders().get("Content-Type")).isEqualTo("application/json");
        }

        @Test
        @DisplayName("Should return httpBody")
        void shouldReturnHttpBody() {
            assertThat(validBuilder().httpBody("{\"key\":\"value\"}").build().getHttpBody())
                    .isEqualTo("{\"key\":\"value\"}");
        }

        @Test
        @DisplayName("Should return null for unset optional fields")
        void shouldReturnNullForUnsetOptionalFields() {
            ResourceRequest request = validBuilder().build();

            assertThat(request.getHttpMethod()).isNull();
            assertThat(request.getHttpUri()).isNull();
            assertThat(request.getHttpHeaders()).isNull();
            assertThat(request.getHttpBody()).isNull();
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complex HTTP headers")
        void shouldHandleComplexHttpHeaders() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("User-Agent", "TestAgent/1.0");
            headers.put("X-Custom-Header", "custom-value");

            ResourceRequest request = validBuilder().httpHeaders(headers).build();

            assertThat(request.getHttpHeaders()).hasSize(3);
            assertThat(request.getHttpHeaders().get("Content-Type")).isEqualTo("application/json");
        }

        @Test
        @DisplayName("Should create multiple independent instances")
        void shouldCreateMultipleIndependentInstances() {
            ResourceRequest request1 = ResourceRequest.builder().ct("ct-1").dpop("dpop-1").build();
            ResourceRequest request2 = ResourceRequest.builder().ct("ct-2").dpop("dpop-2").build();

            assertThat(request1.getCt()).isEqualTo("ct-1");
            assertThat(request2.getCt()).isEqualTo("ct-2");
            assertThat(request1).isNotSameAs(request2);
        }
    }
}
