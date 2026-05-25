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
package ai.shao.aap.rs.core.server.exception;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for ServerErrorCode interface.
 *
 * <p>This test class validates the constants and default methods defined in the ServerErrorCode
 * interface, ensuring proper error code structure.
 *
 * @since 1.0
 */
@DisplayName("ServerErrorCode Test")
class ServerErrorCodeTest {

    /** Test implementation of ServerErrorCode for testing. */
    private enum TestServerErrorCode implements ServerErrorCode {
        TEST_AUTH_ERROR("01", "TestAuthError", "Auth error: {0}"),
        TEST_TOKEN_ERROR("02", "TestTokenError", "Token error: {0}"),
        TEST_VALIDATION_ERROR("03", "TestValidationError", "Validation error: {0}");

        private final String subCode;
        private final String errorName;
        private final String messageTemplate;

        TestServerErrorCode(String subCode, String errorName, String messageTemplate) {
            this.subCode = subCode;
            this.errorName = errorName;
            this.messageTemplate = messageTemplate;
        }

        @Override
        public String getDomainCode() {
            return "01";
        }

        @Override
        public String getSubCode() {
            return subCode;
        }

        @Override
        public String getErrorName() {
            return errorName;
        }

        @Override
        public String getMessageTemplate() {
            return messageTemplate;
        }
    }

    @Test
    @DisplayName("Should have correct system code")
    void shouldHaveCorrectSystemCode() {
        assertThat(ServerErrorCode.SYSTEM_CODE).isEqualTo("11");
    }

    @Test
    @DisplayName("Should have correct domain code for Auth")
    void shouldHaveCorrectDomainCodeForAuth() {
        assertThat(ServerErrorCode.DOMAIN_CODE_AUTH).isEqualTo("01");
    }

    @Test
    @DisplayName("Should have correct domain code for Token")
    void shouldHaveCorrectDomainCodeForToken() {
        assertThat(ServerErrorCode.DOMAIN_CODE_TOKEN).isEqualTo("02");
    }

    @Test
    @DisplayName("Should have correct domain code for Validation")
    void shouldHaveCorrectDomainCodeForValidation() {
        assertThat(ServerErrorCode.DOMAIN_CODE_VALIDATION).isEqualTo("03");
    }

    @Test
    @DisplayName("Should return correct system code from default method")
    void shouldReturnCorrectSystemCodeFromDefaultMethod() {
        assertThat(TestServerErrorCode.TEST_AUTH_ERROR.getSystemCode()).isEqualTo("11");
        assertThat(TestServerErrorCode.TEST_TOKEN_ERROR.getSystemCode()).isEqualTo("11");
        assertThat(TestServerErrorCode.TEST_VALIDATION_ERROR.getSystemCode()).isEqualTo("11");
    }

    @Test
    @DisplayName("Should format message with single parameter")
    void shouldFormatMessageWithSingleParameter() {
        String formatted = TestServerErrorCode.TEST_AUTH_ERROR.formatMessage("test");
        assertThat(formatted).isEqualTo("Auth error: test");
    }

    @Test
    @DisplayName("Should format message with multiple parameters")
    void shouldFormatMessageWithMultipleParameters() {
        String formatted = TestServerErrorCode.TEST_AUTH_ERROR.formatMessage("param1", "param2");
        assertThat(formatted).isEqualTo("Auth error: param1");
    }

    @Test
    @DisplayName("Should format message with null parameters")
    void shouldFormatMessageWithNullParameters() {
        String formatted = TestServerErrorCode.TEST_AUTH_ERROR.formatMessage((Object[]) null);
        assertThat(formatted).isEqualTo("Auth error: {0}");
    }

    @Test
    @DisplayName("Should format message with empty parameters")
    void shouldFormatMessageWithEmptyParameters() {
        String formatted = TestServerErrorCode.TEST_AUTH_ERROR.formatMessage();
        assertThat(formatted).isEqualTo("Auth error: {0}");
    }

    @Test
    @DisplayName("Should generate correct error code for Auth domain")
    void shouldGenerateCorrectErrorCodeForAuthDomain() {
        assertThat(TestServerErrorCode.TEST_AUTH_ERROR.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0101");
    }

    @Test
    @DisplayName("Should generate correct error code for Token domain")
    void shouldGenerateCorrectErrorCodeForTokenDomain() {
        assertThat(TestServerErrorCode.TEST_TOKEN_ERROR.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0102");
    }

    @Test
    @DisplayName("Should generate correct error code for Validation domain")
    void shouldGenerateCorrectErrorCodeForValidationDomain() {
        assertThat(TestServerErrorCode.TEST_VALIDATION_ERROR.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0103");
    }

    @Test
    @DisplayName("Should return correct sub code")
    void shouldReturnCorrectSubCode() {
        assertThat(TestServerErrorCode.TEST_AUTH_ERROR.getSubCode()).isEqualTo("01");
        assertThat(TestServerErrorCode.TEST_TOKEN_ERROR.getSubCode()).isEqualTo("02");
        assertThat(TestServerErrorCode.TEST_VALIDATION_ERROR.getSubCode()).isEqualTo("03");
    }

    @Test
    @DisplayName("Should return correct error name")
    void shouldReturnCorrectErrorName() {
        assertThat(TestServerErrorCode.TEST_AUTH_ERROR.getErrorName()).isEqualTo("TestAuthError");
        assertThat(TestServerErrorCode.TEST_TOKEN_ERROR.getErrorName()).isEqualTo("TestTokenError");
    }

    @Test
    @DisplayName("Should return correct message template")
    void shouldReturnCorrectMessageTemplate() {
        assertThat(TestServerErrorCode.TEST_AUTH_ERROR.getMessageTemplate())
                .isEqualTo("Auth error: {0}");
    }

    @Test
    @DisplayName("Should verify domain codes are sequential")
    void shouldVerifyDomainCodesAreSequential() {
        assertThat(ServerErrorCode.DOMAIN_CODE_AUTH).isEqualTo("01");
        assertThat(ServerErrorCode.DOMAIN_CODE_TOKEN).isEqualTo("02");
        assertThat(ServerErrorCode.DOMAIN_CODE_VALIDATION).isEqualTo("03");
    }
}
