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
package com.alibaba.openagentauth.core.crypto.key.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable metadata about a cryptographic key (identifier, lifecycle timestamps,
 * active flag). Construct via {@link Builder}.
 *
 * @since 1.0
 */
public class KeyInfo {

    private final String keyId;
    private final Instant createdAt;
    private final Instant activatedAt;
    private final boolean active;

    private KeyInfo(String keyId, Instant createdAt, Instant activatedAt, boolean active) {
        this.keyId = keyId;
        this.createdAt = createdAt;
        this.activatedAt = activatedAt;
        this.active = active;
    }

    public String getKeyId() {
        return keyId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getActivatedAt() {
        return activatedAt;
    }

    public boolean isActive() {
        return active;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyInfo keyInfo = (KeyInfo) o;
        return active == keyInfo.active &&
               Objects.equals(keyId, keyInfo.keyId) &&
               Objects.equals(createdAt, keyInfo.createdAt) &&
               Objects.equals(activatedAt, keyInfo.activatedAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, createdAt, activatedAt, active);
    }

    @Override
    public String toString() {
        return "KeyInfo{" +
                "keyId='" + keyId + '\'' +
                ", createdAt=" + createdAt +
                ", activatedAt=" + activatedAt +
                ", active=" + active +
                '}';
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private String keyId;
        private Instant createdAt;
        private Instant activatedAt;
        private boolean active;

        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder createdAt(Instant createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public Builder activatedAt(Instant activatedAt) {
            this.activatedAt = activatedAt;
            return this;
        }

        public Builder active(boolean active) {
            this.active = active;
            return this;
        }

        public KeyInfo build() {
            return new KeyInfo(keyId, createdAt, activatedAt, active);
        }
    }
}
