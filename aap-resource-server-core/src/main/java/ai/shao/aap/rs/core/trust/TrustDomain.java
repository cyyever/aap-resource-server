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
package ai.shao.aap.rs.core.trust;

import ai.shao.aap.rs.core.util.ValidationUtils;

/**
 * Logical scope-of-trust boundary for agent identities. The {@code domainId} is compared against
 * the {@code iss} claim of incoming CTs verbatim — no scheme prefix is stripped.
 */
public record TrustDomain(String domainId) {

    public TrustDomain {
        if (ValidationUtils.isNullOrEmpty(domainId)) {
            throw new IllegalArgumentException("Domain ID cannot be null or empty");
        }
    }
}
