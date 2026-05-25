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

import ai.shao.aap.rs.core.server.exception.ServerErrorCode;

/**
 * Error codes for Validation domain (Request Validation). All Validation error codes follow the
 * format {@code OPEN_AGENT_AUTH_11_03ZZ} (11 = Server system, 03 = Validation domain, ZZ = error
 * within domain).
 */
public enum ValidationErrorCode implements ServerErrorCode {

    /**
     * Request validation failed. Corresponds to {@link ServerValidationException}. Template: {0}
     */
    VALIDATION_FAILED("01", "ServerValidationFailed", "Server validation failed: {0}");

    public static final String DOMAIN_CODE = ServerErrorCode.DOMAIN_CODE_VALIDATION;

    private final String subCode;
    private final String errorName;
    private final String messageTemplate;

    ValidationErrorCode(String subCode, String errorName, String messageTemplate) {
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
