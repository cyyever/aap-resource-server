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
package ai.shao.aap.rs.core.model.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import org.jspecify.annotations.Nullable;

/**
 * Represents a DPoP Proof (DPoP). A DPoP is a JWT that proves possession of the private key
 * corresponding to the public key in the associated Credential Token (CT). It binds to the CT via
 * the {@code wth} claim. Per AAP spec §3 the JOSE header is fixed at {@code {alg=EdDSA,
 * typ=dpop+jwt}} (DPoP also permits {@code jwk}), so those parameters are not carried on this
 * record.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DpopToken(
        Claims claims,
        @JsonProperty("signature") @Nullable String signature,
        @JsonProperty("jwtString") @Nullable String jwtString) {

    /** Required {@code typ} JOSE header value. */
    public static final String MEDIA_TYPE = "dpop+jwt";

    public DpopToken {
        if (claims == null) {
            throw new IllegalStateException("claims is REQUIRED for DPoP");
        }
    }

    /** Audience (aud) — convenience delegate to claims. */
    public @Nullable String getAudience() {
        return claims.audience();
    }

    public Instant getExpirationTime() {
        return claims.expirationTime();
    }

    public @Nullable String getJwtId() {
        return claims.jwtId();
    }

    public String getWorkloadTokenHash() {
        return claims.workloadTokenHash();
    }

    public @Nullable String getAccessTokenHash() {
        return claims.accessTokenHash();
    }

    public boolean isExpired() {
        return claims.isExpired();
    }

    public boolean isValid() {
        return claims.isValid();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private @Nullable Claims claims;
        private @Nullable String signature;
        private @Nullable String jwtString;

        public Builder claims(Claims claims) {
            this.claims = claims;
            return this;
        }

        public Builder signature(String signature) {
            this.signature = signature;
            return this;
        }

        public Builder jwtString(String jwtString) {
            this.jwtString = jwtString;
            return this;
        }

        public DpopToken build() {
            if (claims == null) {
                throw new IllegalStateException("claims is REQUIRED for DPoP");
            }
            return new DpopToken(claims, signature, jwtString);
        }
    }

    /** Claims (Payload) for DPoP Proof (DPoP). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Claims(
            @JsonProperty("aud") @Nullable String audience,
            @JsonProperty("exp") Instant expirationTime,
            @JsonProperty("jti") @Nullable String jwtId,
            @JsonProperty("wth") String workloadTokenHash,
            @JsonProperty("ath") @Nullable String accessTokenHash) {

        public Claims {
            if (workloadTokenHash == null || workloadTokenHash.isEmpty()) {
                throw new IllegalStateException("workloadTokenHash (wth) is REQUIRED");
            }
            if (expirationTime == null) {
                throw new IllegalStateException("expirationTime (exp) is REQUIRED");
            }
        }

        public boolean isExpired() {
            return expirationTime.toEpochMilli() < System.currentTimeMillis();
        }

        public boolean isValid() {
            return System.currentTimeMillis() <= expirationTime.toEpochMilli();
        }

        public static ClaimsBuilder builder() {
            return new ClaimsBuilder();
        }

        public static class ClaimsBuilder {
            private @Nullable String audience;
            private @Nullable Instant expirationTime;
            private @Nullable String jwtId;
            private @Nullable String workloadTokenHash;
            private @Nullable String accessTokenHash;

            public ClaimsBuilder audience(@Nullable String audience) {
                this.audience = audience;
                return this;
            }

            public ClaimsBuilder expirationTime(@Nullable Instant expirationTime) {
                this.expirationTime = expirationTime;
                return this;
            }

            public ClaimsBuilder jwtId(@Nullable String jwtId) {
                this.jwtId = jwtId;
                return this;
            }

            public ClaimsBuilder workloadTokenHash(@Nullable String workloadTokenHash) {
                this.workloadTokenHash = workloadTokenHash;
                return this;
            }

            public ClaimsBuilder accessTokenHash(@Nullable String accessTokenHash) {
                this.accessTokenHash = accessTokenHash;
                return this;
            }

            public Claims build() {
                if (workloadTokenHash == null || workloadTokenHash.isEmpty()) {
                    throw new IllegalStateException("workloadTokenHash (wth) is REQUIRED");
                }
                if (expirationTime == null) {
                    throw new IllegalStateException("expirationTime (exp) is REQUIRED");
                }
                return new Claims(
                        audience, expirationTime, jwtId, workloadTokenHash, accessTokenHash);
            }
        }
    }
}
