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

import ai.shao.aap.rs.core.model.jwk.Jwk;
import ai.shao.aap.rs.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import org.jspecify.annotations.Nullable;

/**
 * Represents a Credential Token (CT). A CT is a JWT that identifies a workload and contains a
 * public key in the {@code cnf} claim used to verify the corresponding DPoP Proof (DPoP). Per AAP
 * spec §3 the JOSE header is fixed at {@code {alg=EdDSA, typ=ct+jwt}}, so neither parameter is
 * carried on this record.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialToken(
        Claims claims,
        @JsonProperty("signature") @Nullable String signature,
        @JsonProperty("jwtString") @Nullable String jwtString) {

    /** Required {@code typ} JOSE header value. */
    public static final String MEDIA_TYPE = "ct+jwt";

    public CredentialToken {
        if (claims == null) {
            throw new IllegalStateException("claims is REQUIRED for CT");
        }
    }

    public @Nullable String getIssuer() {
        return claims.issuer();
    }

    public String getSubject() {
        return claims.subject();
    }

    public Instant getExpirationTime() {
        return claims.expirationTime();
    }

    public @Nullable String getJwtId() {
        return claims.jwtId();
    }

    public String getWorkloadIdentifier() {
        return claims.subject();
    }

    public Claims.Confirmation getConfirmation() {
        return claims.confirmation();
    }

    public Jwk getJwk() {
        return claims.jwk();
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

        public CredentialToken build() {
            if (claims == null) {
                throw new IllegalStateException("claims is REQUIRED for CT");
            }
            return new CredentialToken(claims, signature, jwtString);
        }
    }

    /** Claims (Payload) for Credential Token (CT). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Claims(
            @JsonProperty("iss") @Nullable String issuer,
            @JsonProperty("sub") String subject,
            @JsonProperty("exp") Instant expirationTime,
            @JsonProperty("jti") @Nullable String jwtId,
            @JsonProperty("cnf") Confirmation confirmation) {

        public Claims {
            if (ValidationUtils.isNullOrEmpty(subject)) {
                throw new IllegalStateException("subject (sub) is REQUIRED");
            }
            if (expirationTime == null) {
                throw new IllegalStateException("expirationTime (exp) is REQUIRED");
            }
            if (confirmation == null) {
                throw new IllegalStateException("confirmation (cnf) is REQUIRED");
            }
        }

        /** Workload Identifier alias for subject. */
        public String getWorkloadIdentifier() {
            return subject;
        }

        /** JWK from the confirmation claim. */
        public Jwk jwk() {
            return confirmation.jwk();
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
            private @Nullable String issuer;
            private @Nullable String subject;
            private @Nullable Instant expirationTime;
            private @Nullable String jwtId;
            private @Nullable Confirmation confirmation;

            public ClaimsBuilder issuer(@Nullable String issuer) {
                this.issuer = issuer;
                return this;
            }

            public ClaimsBuilder subject(@Nullable String subject) {
                this.subject = subject;
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

            public ClaimsBuilder confirmation(@Nullable Confirmation confirmation) {
                this.confirmation = confirmation;
                return this;
            }

            public Claims build() {
                if (subject == null || subject.isEmpty()) {
                    throw new IllegalStateException("subject (sub) is REQUIRED");
                }
                if (expirationTime == null) {
                    throw new IllegalStateException("expirationTime (exp) is REQUIRED");
                }
                if (confirmation == null) {
                    throw new IllegalStateException("confirmation (cnf) is REQUIRED");
                }
                return new Claims(issuer, subject, expirationTime, jwtId, confirmation);
            }
        }

        /**
         * Confirmation claim (cnf) structure as defined in RFC 7800. Contains the JWK used to
         * verify the corresponding DPoP.
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public record Confirmation(@JsonProperty("jwk") Jwk jwk) {

            public Confirmation {
                if (jwk == null) {
                    throw new IllegalStateException("jwk is REQUIRED in confirmation (cnf) claim");
                }
            }

            public static ConfirmationBuilder builder() {
                return new ConfirmationBuilder();
            }

            public static class ConfirmationBuilder {
                private @Nullable Jwk jwk;

                public ConfirmationBuilder jwk(Jwk jwk) {
                    this.jwk = jwk;
                    return this;
                }

                public Confirmation build() {
                    if (jwk == null) {
                        throw new IllegalStateException(
                                "jwk is REQUIRED in confirmation (cnf) claim");
                    }
                    return new Confirmation(jwk);
                }
            }
        }
    }
}
