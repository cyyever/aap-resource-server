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
package ai.shao.aap.rs.core.model.jwk;

import ai.shao.aap.rs.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.jspecify.annotations.Nullable;

/**
 * Minimal Ed25519 JSON Web Key as used in AAP CT cnf.jwk and DPoP header.jwk.
 *
 * <p>Per spec §3 only Ed25519 ({@code kty=OKP}, {@code crv=Ed25519}) is permitted, so those fields
 * are wire-only constants emitted by {@link ai.shao.aap.rs.core.crypto.JwkConverter} and not
 * carried on the record itself.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8037">RFC 8037</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Jwk(@JsonProperty("x") String x, @JsonProperty("kid") @Nullable String keyId) {

    public Jwk {
        if (ValidationUtils.isNullOrEmpty(x)) {
            throw new IllegalStateException("x coordinate is REQUIRED");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private @Nullable String x;
        private @Nullable String keyId;

        public Builder x(@Nullable String x) {
            this.x = x;
            return this;
        }

        public Builder keyId(@Nullable String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Jwk build() {
            if (x == null) {
                throw new IllegalStateException("x coordinate is REQUIRED");
            }
            return new Jwk(x, keyId);
        }
    }
}
