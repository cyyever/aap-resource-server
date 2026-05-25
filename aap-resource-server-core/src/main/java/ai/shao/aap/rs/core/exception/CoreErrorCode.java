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
package ai.shao.aap.rs.core.exception;

/**
 * Interface for Core module error codes. Error code format: {@code OPEN_AGENT_AUTH_10_YYZZ} (system
 * 10, YY=domain, ZZ=error).
 */
public interface CoreErrorCode extends ErrorCode {

    /** System code for Core module. */
    String SYSTEM_CODE = "10";

    /** Domain code for Crypto. */
    String DOMAIN_CODE_CRYPTO = "03";

    @Override
    default String getSystemCode() {
        return SYSTEM_CODE;
    }
}
