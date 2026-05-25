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
package ai.shao.aap.rs.core.crypto.key.model;

import org.jspecify.annotations.Nullable;

/**
 * Immutable value object describing how a key should be resolved and managed. If {@code
 * jwksConsumer} is set, the key is resolved from a remote JWKS endpoint; otherwise, it is resolved
 * from a local key store via the configured {@code provider}.
 */
public record KeyDefinition(
        String keyId, @Nullable String provider, @Nullable String jwksConsumer) {

    public KeyDefinition {
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalArgumentException("KeyDefinition keyId cannot be null or empty");
        }
    }

    public boolean isRemoteKey() {
        return jwksConsumer != null && !jwksConsumer.isBlank();
    }

    public boolean isLocalKey() {
        return !isRemoteKey();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {

        private @Nullable String keyId;
        private @Nullable String provider;
        private @Nullable String jwksConsumer;

        private Builder() {}

        public Builder keyId(@Nullable String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder provider(@Nullable String provider) {
            this.provider = provider;
            return this;
        }

        public Builder jwksConsumer(@Nullable String jwksConsumer) {
            this.jwksConsumer = jwksConsumer;
            return this;
        }

        public KeyDefinition build() {
            if (keyId == null || keyId.isBlank()) {
                throw new IllegalArgumentException("KeyDefinition keyId cannot be null or empty");
            }
            return new KeyDefinition(keyId, provider, jwksConsumer);
        }
    }
}
