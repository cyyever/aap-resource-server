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
package ai.shao.openagentauth.core.server.model.request;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ResourceRequest Tests")
class ResourceRequestTest {

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build request with wit")
        void shouldBuildRequestWithWit() {
            ResourceRequest request = ResourceRequest.builder()
                .wit("wit-token")
                .build();

            assertThat(request.getWit()).isEqualTo("wit-token");
        }

        @Test
        @DisplayName("Should build request with wit and wpt")
        void shouldBuildRequestWithWitAndWpt() {
            ResourceRequest request = ResourceRequest.builder()
                .wit("wit-token")
                .wpt("wpt-token")
                .build();

            assertThat(request.getWit()).isEqualTo("wit-token");
            assertThat(request.getWpt()).isEqualTo("wpt-token");
        }

        @Test
        @DisplayName("Should build request with HTTP information")
        void shouldBuildRequestWithHttpInformation() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");

            ResourceRequest request = ResourceRequest.builder()
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
        @DisplayName("Should build request with all fields")
        void shouldBuildRequestWithAllFields() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");

            ResourceRequest request = ResourceRequest.builder()
                .wit("wit-token")
                .wpt("wpt-token")
                .httpMethod("GET")
                .httpUri("/api/resource")
                .httpHeaders(headers)
                .httpBody("")
                .build();

            assertThat(request.getWit()).isEqualTo("wit-token");
            assertThat(request.getWpt()).isEqualTo("wpt-token");
            assertThat(request.getHttpMethod()).isEqualTo("GET");
            assertThat(request.getHttpUri()).isEqualTo("/api/resource");
            assertThat(request.getHttpHeaders()).hasSize(1);
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            ResourceRequest request = ResourceRequest.builder()
                .wit("wit-token")
                .wpt("wpt-token")
                .httpMethod("POST")
                .httpUri("/api/resource")
                .build();

            assertThat(request).isNotNull();
        }

        @Test
        @DisplayName("Should handle null values")
        void shouldHandleNullValues() {
            ResourceRequest request = ResourceRequest.builder()
                .wit(null)
                .wpt(null)
                .httpMethod(null)
                .httpUri(null)
                .httpHeaders(null)
                .httpBody(null)
                .build();

            assertThat(request.getWit()).isNull();
            assertThat(request.getWpt()).isNull();
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
        @DisplayName("Should return wit")
        void shouldReturnWit() {
            ResourceRequest request = ResourceRequest.builder()
                .wit("wit-token")
                .build();

            assertThat(request.getWit()).isEqualTo("wit-token");
        }

        @Test
        @DisplayName("Should return wpt")
        void shouldReturnWpt() {
            ResourceRequest request = ResourceRequest.builder()
                .wpt("wpt-token")
                .build();

            assertThat(request.getWpt()).isEqualTo("wpt-token");
        }

        @Test
        @DisplayName("Should return httpMethod")
        void shouldReturnHttpMethod() {
            ResourceRequest request = ResourceRequest.builder()
                .httpMethod("POST")
                .build();

            assertThat(request.getHttpMethod()).isEqualTo("POST");
        }

        @Test
        @DisplayName("Should return httpUri")
        void shouldReturnHttpUri() {
            ResourceRequest request = ResourceRequest.builder()
                .httpUri("/api/resource")
                .build();

            assertThat(request.getHttpUri()).isEqualTo("/api/resource");
        }

        @Test
        @DisplayName("Should return httpHeaders")
        void shouldReturnHttpHeaders() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");

            ResourceRequest request = ResourceRequest.builder()
                .httpHeaders(headers)
                .build();

            assertThat(request.getHttpHeaders()).hasSize(1);
            assertThat(request.getHttpHeaders().get("Content-Type")).isEqualTo("application/json");
        }

        @Test
        @DisplayName("Should return httpBody")
        void shouldReturnHttpBody() {
            ResourceRequest request = ResourceRequest.builder()
                .httpBody("{\"key\":\"value\"}")
                .build();

            assertThat(request.getHttpBody()).isEqualTo("{\"key\":\"value\"}");
        }

        @Test
        @DisplayName("Should return null for missing fields")
        void shouldReturnNullForMissingFields() {
            ResourceRequest request = ResourceRequest.builder()
                .wit("wit-token")
                .build();

            assertThat(request.getWpt()).isNull();
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

            ResourceRequest request = ResourceRequest.builder()
                .httpHeaders(headers)
                .build();

            assertThat(request.getHttpHeaders()).hasSize(3);
            assertThat(request.getHttpHeaders().get("Content-Type")).isEqualTo("application/json");
        }

        @Test
        @DisplayName("Should create multiple independent instances")
        void shouldCreateMultipleIndependentInstances() {
            ResourceRequest request1 = ResourceRequest.builder()
                .wit("wit-1")
                .build();

            ResourceRequest request2 = ResourceRequest.builder()
                .wit("wit-2")
                .build();

            assertThat(request1.getWit()).isEqualTo("wit-1");
            assertThat(request2.getWit()).isEqualTo("wit-2");
            assertThat(request1).isNotSameAs(request2);
        }
    }
}
