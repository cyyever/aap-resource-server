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
package ai.shao.aap.rs.core.model.identity;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import org.jspecify.annotations.Nullable;

/** Represents the identity of an AI agent. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AgentIdentity(
        @JsonProperty("version") @Nullable String version,
        @JsonProperty("id") @Nullable String id,
        @JsonProperty("issuer") @Nullable String issuer,
        @JsonProperty("issued_to") @Nullable String issuedTo,
        @JsonProperty("issued_for") @Nullable IssuedFor issuedFor,
        @JsonProperty("issuance_date") @Nullable Instant issuanceDate,
        @JsonProperty("valid_from") @Nullable Instant validFrom,
        @JsonProperty("expires") @Nullable Instant expires) {

    public static Builder builder() {
        return new Builder();
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record IssuedFor(
            @JsonProperty("platform") @Nullable String platform,
            @JsonProperty("client") @Nullable String client,
            @JsonProperty("client_instance") @Nullable String clientInstance) {

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private @Nullable String platform;
            private @Nullable String client;
            private @Nullable String clientInstance;

            public Builder platform(@Nullable String platform) {
                this.platform = platform;
                return this;
            }

            public Builder client(@Nullable String client) {
                this.client = client;
                return this;
            }

            public Builder clientInstance(@Nullable String clientInstance) {
                this.clientInstance = clientInstance;
                return this;
            }

            public IssuedFor build() {
                return new IssuedFor(platform, client, clientInstance);
            }
        }
    }

    public static class Builder {
        private @Nullable String version = "1.0";
        private @Nullable String id;
        private @Nullable String issuer;
        private @Nullable String issuedTo;
        private @Nullable IssuedFor issuedFor;
        private @Nullable Instant issuanceDate;
        private @Nullable Instant validFrom;
        private @Nullable Instant expires;

        public Builder version(@Nullable String version) {
            this.version = version;
            return this;
        }

        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }

        public Builder issuer(@Nullable String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder issuedTo(@Nullable String issuedTo) {
            this.issuedTo = issuedTo;
            return this;
        }

        public Builder issuedFor(@Nullable IssuedFor issuedFor) {
            this.issuedFor = issuedFor;
            return this;
        }

        public Builder issuanceDate(@Nullable Instant issuanceDate) {
            this.issuanceDate = issuanceDate;
            return this;
        }

        public Builder validFrom(@Nullable Instant validFrom) {
            this.validFrom = validFrom;
            return this;
        }

        public Builder expires(@Nullable Instant expires) {
            this.expires = expires;
            return this;
        }

        public AgentIdentity build() {
            return new AgentIdentity(
                    version, id, issuer, issuedTo, issuedFor, issuanceDate, validFrom, expires);
        }
    }
}
