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

import ai.shao.aap.rs.core.server.exception.ServerErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ValidationErrorCode Test")
class ValidationErrorCodeTest {

    @Test
    @DisplayName("Should have correct domain code")
    void shouldHaveCorrectDomainCode() {
        assertThat(ValidationErrorCode.DOMAIN_CODE).isEqualTo("03");
    }

    @Test
    @DisplayName("Should have correct system code")
    void shouldHaveCorrectSystemCode() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getSystemCode()).isEqualTo("11");
    }

    @Test
    @DisplayName("Should generate correct error code for VALIDATION_FAILED")
    void shouldGenerateCorrectErrorCodeForValidationFailed() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0301");
    }

    @Test
    @DisplayName("Should have correct sub codes")
    void shouldHaveCorrectSubCodes() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getSubCode()).isEqualTo("01");
    }

    @Test
    @DisplayName("Should have correct error names")
    void shouldHaveCorrectErrorNames() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getErrorName())
                .isEqualTo("ServerValidationFailed");
    }

    @Test
    @DisplayName("Should have correct message templates")
    void shouldHaveCorrectMessageTemplates() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getMessageTemplate())
                .isEqualTo("Server validation failed: {0}");
    }

    @Test
    @DisplayName("Should format messages correctly")
    void shouldFormatMessagesCorrectly() {
        String validationMessage =
                ValidationErrorCode.VALIDATION_FAILED.formatMessage("Invalid parameter");
        assertThat(validationMessage).isEqualTo("Server validation failed: Invalid parameter");
    }

    @Test
    @DisplayName("Should format message with null parameters")
    void shouldFormatMessageWithNullParameters() {
        String message = ValidationErrorCode.VALIDATION_FAILED.formatMessage((Object[]) null);
        assertThat(message).isEqualTo("Server validation failed: {0}");
    }

    @Test
    @DisplayName("Should implement ServerErrorCode")
    void shouldImplementServerErrorCode() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED).isInstanceOf(ServerErrorCode.class);
    }
}
