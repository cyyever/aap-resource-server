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
package ai.shao.aap.rs.core.exception.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Crypto Error Code Test")
class CryptoErrorCodeTest {

    @Test
    @DisplayName("Should verify KEY_RESOLUTION_FAILED error code properties")
    void shouldVerifyKeyResolutionFailedErrorCodeProperties() {
        CryptoErrorCode errorCode = CryptoErrorCode.KEY_RESOLUTION_FAILED;

        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0306");
        assertThat(errorCode.getDomainCode()).isEqualTo("03");
        assertThat(errorCode.getSubCode()).isEqualTo("06");
        assertThat(errorCode.getErrorName()).isEqualTo("KeyResolutionFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Key resolution failed: {0}");
    }

    @Test
    @DisplayName("Should verify all error codes have correct domain code")
    void shouldVerifyAllErrorCodesHaveCorrectDomainCode() {
        for (CryptoErrorCode errorCode : CryptoErrorCode.values()) {
            assertThat(errorCode.getDomainCode()).isEqualTo("03");
        }
    }

    @Test
    @DisplayName("Should verify all error codes have correct system code")
    void shouldVerifyAllErrorCodesHaveCorrectSystemCode() {
        for (CryptoErrorCode errorCode : CryptoErrorCode.values()) {
            assertThat(errorCode.getSystemCode()).isEqualTo("10");
        }
    }

    @Test
    @DisplayName("Should verify domain code constant")
    void shouldVerifyDomainCodeConstant() {
        assertThat(CryptoErrorCode.DOMAIN_CODE).isEqualTo("03");
    }

    @Test
    @DisplayName("Should verify error code format consistency")
    void shouldVerifyErrorCodeFormatConsistency() {
        for (CryptoErrorCode errorCode : CryptoErrorCode.values()) {
            assertThat(errorCode.getErrorCode()).matches("OPEN_AGENT_AUTH_10_03\\d{2}");
            assertThat(errorCode.getErrorCode()).hasSize(23);
        }
    }
}
