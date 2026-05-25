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

import ai.shao.aap.rs.core.exception.ErrorCode;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for Server exception base classes and error code functionality.
 *
 * <p>This test class validates the core functionality of the Server exception hierarchy, including
 * message formatting, error code handling, and parameter passing.
 *
 * @since 1.0
 */
@DisplayName("Server Exception Base Classes Test")
class ServerExceptionTest {

    /** Test error code implementation for Server module. */
    private enum TestServerErrorCode implements ServerErrorCode {
        TEST_AUTH_FAILED("01", "TestAuthFailed", "Server authentication failed: {0}"),
        TEST_TOKEN_ERROR("02", "TestTokenError", "Server token generation failed: {0}"),
        TEST_VALIDATION_ERROR("03", "TestValidationError", "Server validation failed: {0} - {1}");

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
            return subCode;
        }

        @Override
        public String getSubCode() {
            return "01";
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

    /** Test Server exception implementation. */
    private static class TestServerException extends ServerException {
        public TestServerException(ErrorCode errorCode) {
            super(errorCode);
        }

        public TestServerException(ErrorCode errorCode, Object... errorParams) {
            super(errorCode, errorParams);
        }

        public TestServerException(
                ErrorCode errorCode, List<Object> errorParams, Map<String, Object> context) {
            super(errorCode, errorParams, context);
        }

        public TestServerException(ErrorCode errorCode, Throwable cause) {
            super(errorCode, cause);
        }

        public TestServerException(ErrorCode errorCode, Throwable cause, Object... errorParams) {
            super(errorCode, cause, errorParams);
        }

        public TestServerException(
                ErrorCode errorCode,
                List<Object> errorParams,
                Map<String, Object> context,
                Throwable cause) {
            super(errorCode, errorParams, context, cause);
        }
    }

    @Test
    @DisplayName("Test ServerErrorCode system code constant")
    void testServerErrorCodeSystemCode() {
        assertThat(ServerErrorCode.SYSTEM_CODE).isEqualTo("11");
    }

    @Test
    @DisplayName("Test ServerErrorCode domain codes")
    void testServerErrorCodeDomainCodes() {
        assertThat(ServerErrorCode.DOMAIN_CODE_AUTH).isEqualTo("01");
        assertThat(ServerErrorCode.DOMAIN_CODE_TOKEN).isEqualTo("02");
        assertThat(ServerErrorCode.DOMAIN_CODE_VALIDATION).isEqualTo("03");
    }

    @Test
    @DisplayName("Test ErrorCode formatMessage with single parameter")
    void testFormatMessageWithSingleParameter() {
        String message = TestServerErrorCode.TEST_AUTH_FAILED.formatMessage("john.doe");
        assertThat(message).isEqualTo("Server authentication failed: john.doe");
    }

    @Test
    @DisplayName("Test ErrorCode formatMessage with multiple parameters")
    void testFormatMessageWithMultipleParameters() {
        String message =
                TestServerErrorCode.TEST_VALIDATION_ERROR.formatMessage(
                        "username", "cannot be empty");
        assertThat(message).isEqualTo("Server validation failed: username - cannot be empty");
    }

    @Test
    @DisplayName("Test ServerException with error code only")
    void testServerExceptionWithErrorCodeOnly() {
        TestServerException exception =
                new TestServerException(TestServerErrorCode.TEST_AUTH_FAILED);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Server authentication failed: {0}");
        assertThat(exception.getErrorParams()).isNull();
    }

    @Test
    @DisplayName("Test ServerException with varargs parameters")
    void testServerExceptionWithVarargsParameters() {
        TestServerException exception =
                new TestServerException(TestServerErrorCode.TEST_AUTH_FAILED, "john.doe");
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server authentication failed: john.doe");
        assertThat(exception.getErrorParams()).containsExactly("john.doe");
    }

    @Test
    @DisplayName("Test ServerException with multiple varargs parameters")
    void testServerExceptionWithMultipleVarargsParameters() {
        TestServerException exception =
                new TestServerException(
                        TestServerErrorCode.TEST_VALIDATION_ERROR, "username", "cannot be empty");
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server validation failed: username - cannot be empty");
        assertThat(exception.getErrorParams()).containsExactly("username", "cannot be empty");
    }

    @Test
    @DisplayName("Test ServerException with error params list and context")
    void testServerExceptionWithErrorParamsListAndContext() {
        List<Object> errorParams = Arrays.asList("john.doe");
        Map<String, Object> context = new HashMap<>();
        context.put("userId", "12345");
        context.put("ipAddress", "192.168.1.1");

        TestServerException exception =
                new TestServerException(TestServerErrorCode.TEST_AUTH_FAILED, errorParams, context);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server authentication failed: john.doe");
        assertThat(exception.getErrorParams()).containsExactly("john.doe");
        assertThat(exception.getContext()).containsExactlyInAnyOrderEntriesOf(context);
    }

    @Test
    @DisplayName("Test ServerException with cause")
    void testServerExceptionWithCause() {
        Throwable cause = new RuntimeException("Root cause");
        TestServerException exception =
                new TestServerException(TestServerErrorCode.TEST_AUTH_FAILED, cause);

        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
    }

    @Test
    @DisplayName("Test ServerException with cause and varargs parameters")
    void testServerExceptionWithCauseAndVarargsParameters() {
        Throwable cause = new RuntimeException("Root cause");
        TestServerException exception =
                new TestServerException(TestServerErrorCode.TEST_AUTH_FAILED, cause, "john.doe");

        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server authentication failed: john.doe");
    }

    @Test
    @DisplayName("Test ServerException with all parameters")
    void testServerExceptionWithAllParameters() {
        List<Object> errorParams = Arrays.asList("username", "cannot be empty");
        Map<String, Object> context = new HashMap<>();
        context.put("field", "username");
        Throwable cause = new RuntimeException("Validation failed");

        TestServerException exception =
                new TestServerException(
                        TestServerErrorCode.TEST_VALIDATION_ERROR, errorParams, context, cause);

        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage())
                .isEqualTo("Server validation failed: username - cannot be empty");
        assertThat(exception.getErrorParams()).containsExactly("username", "cannot be empty");
        assertThat(exception.getContext()).containsExactlyInAnyOrderEntriesOf(context);
    }

    @Test
    @DisplayName("Test error code properties")
    void testErrorCodeProperties() {
        TestServerErrorCode errorCode = TestServerErrorCode.TEST_AUTH_FAILED;

        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(errorCode.getErrorName()).isEqualTo("TestAuthFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Server authentication failed: {0}");
    }

    @Test
    @DisplayName("Test exception toString")
    void testExceptionToString() {
        TestServerException exception =
                new TestServerException(TestServerErrorCode.TEST_AUTH_FAILED, "john.doe");

        String toString = exception.toString();
        assertThat(toString).contains("TestServerException");
        assertThat(toString).contains("errorCode='OPEN_AGENT_AUTH_11_0101'");
        assertThat(toString).contains("formattedMessage='Server authentication failed: john.doe'");
    }

    @Test
    @DisplayName("Test errorParams is unmodifiable")
    void testErrorParamsIsUnmodifiable() {
        TestServerException exception =
                new TestServerException(TestServerErrorCode.TEST_AUTH_FAILED, "john.doe");

        List<Object> errorParams = exception.getErrorParams();
        assertThat(errorParams).isNotNull();

        // Attempting to modify should throw UnsupportedOperationException
        try {
            errorParams.add("another.param");
            assertThat(false).isTrue();
        } catch (UnsupportedOperationException e) {
            assertThat(true).isTrue();
        }
    }
}
