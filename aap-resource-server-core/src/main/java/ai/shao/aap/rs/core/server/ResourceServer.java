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
package ai.shao.aap.rs.core.server;

import ai.shao.aap.rs.core.server.exception.validation.ServerValidationException;
import ai.shao.aap.rs.core.server.model.request.ResourceRequest;
import ai.shao.aap.rs.core.server.model.validation.ValidationResult;

/**
 * Resource Server actor interface. Validates incoming requests by chaining the CT (delegation) and
 * DPoP (per-request) validators.
 */
public interface ResourceServer {

    /**
     * Validates an incoming request: CT signature/claims, then DPoP signature/integrity. Fails fast
     * — a CT failure short-circuits before DPoP validation runs.
     *
     * @param request the incoming request
     * @return validation result with per-token outcomes
     * @throws ServerValidationException if token parsing fails before validation can run
     */
    ValidationResult validateRequest(ResourceRequest request) throws ServerValidationException;
}
