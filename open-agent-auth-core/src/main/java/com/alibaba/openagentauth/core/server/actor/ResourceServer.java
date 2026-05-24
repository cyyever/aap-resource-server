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
package com.alibaba.openagentauth.core.server.actor;

import com.alibaba.openagentauth.core.server.model.request.ResourceRequest;
import com.alibaba.openagentauth.core.server.model.validation.ValidationResult;
import com.alibaba.openagentauth.core.server.exception.validation.ServerValidationException;

/**
 * Resource Server actor interface. Validates incoming requests by chaining
 * WIT (workload identity) and WPT (workload proof) validators. After the M1
 * retrofit these become CT (delegation) and DPoP (per-request).
 *
 * @since 1.0
 */
public interface ResourceServer {

    /**
     * Validates an incoming request: WIT signature/claims, then WPT signature/integrity.
     * Fails fast — a WIT failure short-circuits before WPT validation runs.
     *
     * @param request the incoming request
     * @return validation result with per-token outcomes
     * @throws ServerValidationException if token parsing fails before validation can run
     */
    ValidationResult validateRequest(ResourceRequest request) throws ServerValidationException;
}
