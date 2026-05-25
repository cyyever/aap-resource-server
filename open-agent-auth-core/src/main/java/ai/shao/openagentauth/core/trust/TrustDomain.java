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
package ai.shao.openagentauth.core.trust;

import ai.shao.openagentauth.core.util.ValidationUtils;

import java.util.Objects;

/**
 * Represents a trust domain: a logical boundary that defines a scope of trust for
 * agent identities. The identifier is compared against the {@code iss} claim of
 * incoming CTs verbatim — no scheme prefix is stripped.
 */
public class TrustDomain {

    private final String domainId;

    public TrustDomain(String domainId) {
        if (ValidationUtils.isNullOrEmpty(domainId)) {
            throw new IllegalArgumentException("Domain ID cannot be null or empty");
        }
        this.domainId = domainId;
    }

    public String getDomainId() {
        return domainId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrustDomain that = (TrustDomain) o;
        return Objects.equals(domainId, that.domainId);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(domainId);
    }
    
    @Override
    public String toString() {
        return "TrustDomain{" +
                "domainId='" + domainId + '\'' +
                '}';
    }
}