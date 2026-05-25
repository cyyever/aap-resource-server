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

import ai.shao.aap.rs.core.exception.CoreErrorCode;

/**
 * Error codes for Crypto domain.
 *
 * <p>This enum defines error codes for cryptographic operations in the Core module. All crypto
 * error codes follow the format: OPEN_AGENT_AUTH_10_03ZZ
 *
 * <p><b>Error Code Format:</b> OPEN_AGENT_AUTH_10_03ZZ
 *
 * <ul>
 *   <li><b>10</b>: Core system code
 *   <li><b>03</b>: Crypto domain code
 *   <li><b>ZZ</b>: Error code (unique within Crypto domain)
 * </ul>
 */
public enum CryptoErrorCode implements CoreErrorCode {

    /**
     * Key resolution operation failed. Corresponds to {@link KeyResolutionException}. Template: {0}
     */
    KEY_RESOLUTION_FAILED("06", "KeyResolutionFailed", "Key resolution failed: {0}");

    public static final String DOMAIN_CODE = CoreErrorCode.DOMAIN_CODE_CRYPTO;

    private final String subCode;
    private final String errorName;
    private final String messageTemplate;

    CryptoErrorCode(String subCode, String errorName, String messageTemplate) {
        this.subCode = subCode;
        this.errorName = errorName;
        this.messageTemplate = messageTemplate;
    }

    @Override
    public String getDomainCode() {
        return DOMAIN_CODE;
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
