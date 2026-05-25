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

@DisplayName("Crypto Exception Test")
class CryptoExceptionTest {

    @Test
    @DisplayName("Test CryptoErrorCode error code format")
    void testCryptoErrorCodeFormat() {
        assertThat(CryptoErrorCode.KEY_RESOLUTION_FAILED.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_10_0306");
    }

    @Test
    @DisplayName("Test CryptoErrorCode domain code")
    void testCryptoErrorCodeDomainCode() {
        assertThat(CryptoErrorCode.KEY_RESOLUTION_FAILED.getDomainCode()).isEqualTo("03");
    }

    @Test
    @DisplayName("Test CryptoErrorCode sub code")
    void testCryptoErrorCodeSubCode() {
        assertThat(CryptoErrorCode.KEY_RESOLUTION_FAILED.getSubCode()).isEqualTo("06");
    }

    @Test
    @DisplayName("Test CryptoErrorCode system code")
    void testCryptoErrorCodeSystemCode() {
        assertThat(CryptoErrorCode.KEY_RESOLUTION_FAILED.getSystemCode()).isEqualTo("10");
    }

    @Test
    @DisplayName("Test CryptoErrorCode error names")
    void testCryptoErrorCodeErrorNames() {
        assertThat(CryptoErrorCode.KEY_RESOLUTION_FAILED.getErrorName())
                .isEqualTo("KeyResolutionFailed");
    }

    @Test
    @DisplayName("Test CryptoErrorCode domain code constant")
    void testCryptoErrorCodeDomainCodeConstant() {
        assertThat(CryptoErrorCode.DOMAIN_CODE).isEqualTo("03");
    }
}
