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

import ai.shao.aap.rs.core.exception.ErrorCode;

/**
 * Interface for Server module error codes. Error code format: {@code OPEN_AGENT_AUTH_11_YYZZ}
 * (system 11, YY=domain, ZZ=error).
 */
public interface ServerErrorCode extends ErrorCode {

    /** System code for Server module. */
    String SYSTEM_CODE = "11";

    /** Domain code for Auth (Authentication). */
    String DOMAIN_CODE_AUTH = "01";

    /** Domain code for Token (Token Validation). */
    String DOMAIN_CODE_TOKEN = "02";

    /** Domain code for Validation (Request Validation). */
    String DOMAIN_CODE_VALIDATION = "03";

    @Override
    default String getSystemCode() {
        return SYSTEM_CODE;
    }
}
