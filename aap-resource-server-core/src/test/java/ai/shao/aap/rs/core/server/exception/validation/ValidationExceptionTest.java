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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Test class for Validation domain exceptions in the Server module. */
@DisplayName("Validation Exception Test")
class ValidationExceptionTest {

    @Test
    @DisplayName("Test ServerValidationException with message")
    void testServerValidationExceptionWithMessage() {
        ServerValidationException exception = new ServerValidationException("Validation failed");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server validation failed: Validation failed");
        assertThat(exception.getErrorParams()).containsExactly("Validation failed");
        assertThat(exception.getFailedLayer()).isEqualTo(0);
    }

    @Test
    @DisplayName("Test ServerValidationException with message and failed layer")
    void testServerValidationExceptionWithMessageAndFailedLayer() {
        ServerValidationException exception = new ServerValidationException(2, "Validation failed");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server validation failed: Validation failed");
        assertThat(exception.getErrorParams()).containsExactly("Validation failed");
        assertThat(exception.getFailedLayer()).isEqualTo(2);
    }

    @Test
    @DisplayName("Test ServerValidationException with message and cause")
    void testServerValidationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Invalid parameter");
        ServerValidationException exception =
                new ServerValidationException("Validation failed", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server validation failed: Validation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getFailedLayer()).isEqualTo(0);
    }

    @Test
    @DisplayName("Test ServerValidationException with message, failed layer and cause")
    void testServerValidationExceptionWithMessageFailedLayerAndCause() {
        Throwable cause = new RuntimeException("Invalid parameter");
        ServerValidationException exception =
                new ServerValidationException(3, "Validation failed", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server validation failed: Validation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getFailedLayer()).isEqualTo(3);
    }

    @Test
    @DisplayName("Test ValidationErrorCode properties")
    void testValidationErrorCodeProperties() {
        assertThat(ValidationErrorCode.DOMAIN_CODE).isEqualTo("03");

        assertThat(ValidationErrorCode.VALIDATION_FAILED.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getErrorName())
                .isEqualTo("ServerValidationFailed");
    }

    @Test
    @DisplayName("Test ValidationErrorCode formatMessage")
    void testValidationErrorCodeFormatMessage() {
        String message = ValidationErrorCode.VALIDATION_FAILED.formatMessage("username is empty");
        assertThat(message).isEqualTo("Server validation failed: username is empty");
    }
}
