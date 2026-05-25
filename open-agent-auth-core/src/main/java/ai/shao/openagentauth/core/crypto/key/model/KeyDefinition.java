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
package ai.shao.openagentauth.core.crypto.key.model;

import org.jspecify.annotations.Nullable;

import java.util.Objects;

/**
 * Immutable value object describing how a key should be resolved and managed.
 * If {@code jwksConsumer} is set, the key is resolved from a remote JWKS endpoint;
 * otherwise, it is resolved from a local key store via the configured {@code provider}.
 */
public final class KeyDefinition {

    private final String keyId;
    private final @Nullable String provider;
    private final @Nullable String jwksConsumer;

    private KeyDefinition(String keyId, @Nullable String provider, @Nullable String jwksConsumer) {
        this.keyId = keyId;
        this.provider = provider;
        this.jwksConsumer = jwksConsumer;
    }

    public String getKeyId() {
        return keyId;
    }

    public @Nullable String getProvider() {
        return provider;
    }

    public @Nullable String getJwksConsumer() {
        return jwksConsumer;
    }

    public boolean isRemoteKey() {
        return jwksConsumer != null && !jwksConsumer.isBlank();
    }

    public boolean isLocalKey() {
        return !isRemoteKey();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyDefinition that = (KeyDefinition) o;
        return Objects.equals(keyId, that.keyId) &&
                Objects.equals(provider, that.provider) &&
                Objects.equals(jwksConsumer, that.jwksConsumer);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, provider, jwksConsumer);
    }

    @Override
    public String toString() {
        return "KeyDefinition{" +
                "keyId='" + keyId + '\'' +
                ", provider='" + provider + '\'' +
                ", jwksConsumer='" + jwksConsumer + '\'' +
                '}';
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {

        private @Nullable String keyId;
        private @Nullable String provider;
        private @Nullable String jwksConsumer;

        private Builder() {
        }

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
