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
package ai.shao.aap.rs.core.server.exception.validation;

import static org.assertj.core.api.Assertions.assertThat;

import ai.shao.aap.rs.core.server.exception.ServerException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for ServerValidationException.
 *
 * <p>This test class validates the functionality of the framework validation exception, including
 * constructors, message formatting, cause chaining, and failed layer tracking.
 *
 * @since 1.0
 */
@DisplayName("ServerValidationException Test")
class ServerValidationExceptionTest {

    @Test
    @DisplayName("Should create exception with message only")
    void shouldCreateExceptionWithMessageOnly() {
        ServerValidationException exception =
                new ServerValidationException("Request validation failed");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server validation failed: Request validation failed");
        assertThat(exception.getMessage()).contains("Request validation failed");
        assertThat(exception.getCause()).isNull();
        assertThat(exception.getFailedLayer()).isEqualTo(0);
    }

    @Test
    @DisplayName("Should create exception with message and failed layer")
    void shouldCreateExceptionWithMessageAndFailedLayer() {
        ServerValidationException exception =
                new ServerValidationException(2, "Layer 2 validation failed");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server validation failed: Layer 2 validation failed");
        assertThat(exception.getFailedLayer()).isEqualTo(2);
    }

    @Test
    @DisplayName("Should create exception with message and cause")
    void shouldCreateExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Validation logic error");
        ServerValidationException exception =
                new ServerValidationException("Cannot validate request", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server validation failed: Cannot validate request");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getFailedLayer()).isEqualTo(0);
    }

    @Test
    @DisplayName("Should create exception with message, failed layer, and cause")
    void shouldCreateExceptionWithMessageFailedLayerAndCause() {
        Throwable cause = new RuntimeException("Layer 3 error");
        ServerValidationException exception =
                new ServerValidationException(3, "Layer 3 validation failed", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server validation failed: Layer 3 validation failed");
        assertThat(exception.getFailedLayer()).isEqualTo(3);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new NullPointerException("Missing field");
        Throwable intermediateCause = new RuntimeException("Validation failed", rootCause);
        ServerValidationException exception =
                new ServerValidationException("Validation error", intermediateCause);

        assertThat(exception.getCause()).isEqualTo(intermediateCause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should be instance of ValidationException")
    void shouldBeInstanceOfValidationException() {
        ServerValidationException exception = new ServerValidationException("test error");

        assertThat(exception).isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("Should be instance of ServerException")
    void shouldBeInstanceOfServerException() {
        ServerValidationException exception = new ServerValidationException("test error");

        assertThat(exception).isInstanceOf(ServerException.class);
    }

    @Test
    @DisplayName("Should have correct error code constant")
    void shouldHaveCorrectErrorCodeConstant() {
        ServerValidationException exception = new ServerValidationException("test");

        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_11_03");
        assertThat(exception.getErrorCode()).endsWith("01");
    }

    @Test
    @DisplayName("Should handle empty message")
    void shouldHandleEmptyMessage() {
        ServerValidationException exception = new ServerValidationException("");

        assertThat(exception.getFormattedMessage()).isEqualTo("Server validation failed: ");
        assertThat(exception.getErrorParams()).containsExactly("");
    }

    @Test
    @DisplayName("Should handle all valid layers")
    void shouldHandleAllValidLayers() {
        for (int layer = 0; layer <= 4; layer++) {
            ServerValidationException exception =
                    new ServerValidationException(layer, "Layer " + layer + " error");
            assertThat(exception.getFailedLayer()).isEqualTo(layer);
        }
    }

    @Test
    @DisplayName("Should handle null in exception chain")
    void shouldHandleNullInExceptionChain() {
        ServerValidationException exception = new ServerValidationException("test error", null);

        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should track failed layer when cause is present")
    void shouldTrackFailedLayerWhenCauseIsPresent() {
        Throwable cause = new RuntimeException("Error");
        ServerValidationException exception =
                new ServerValidationException(4, "Layer 4 error", cause);

        assertThat(exception.getFailedLayer()).isEqualTo(4);
        assertThat(exception.getCause()).isEqualTo(cause);
    }
}
