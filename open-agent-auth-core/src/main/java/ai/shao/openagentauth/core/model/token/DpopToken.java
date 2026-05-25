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
package ai.shao.openagentauth.core.model.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;

/**
 * Represents a DPoP Proof (DPoP). A DPoP is a JWT that proves possession
 * of the private key corresponding to the public key in the associated Workload
 * Identity Token (CT). It binds to the CT via the {@code wth} claim. Per AAP
 * spec §3 the JOSE header is fixed at {@code {alg=EdDSA, typ=dpop+jwt}} (DPoP
 * adds {@code jwk}), so the typ/alg parameters are not carried on this record.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DpopToken(
        Claims claims,
        @JsonProperty("signature") String signature,
        @JsonProperty("jwtString") String jwtString) {

    /** Required {@code typ} JOSE header value. */
    public static final String MEDIA_TYPE = "dpop+jwt";

    public DpopToken {
        if (claims == null) {
            throw new IllegalStateException("claims is REQUIRED for DPoP");
        }
    }

    /** Audience (aud) — convenience delegate to claims. */
    public String getAudience()           { return claims != null ? claims.audience()             : null; }
    public Date   getExpirationTime()     { return claims != null ? claims.expirationTime()       : null; }
    public String getJwtId()              { return claims != null ? claims.jwtId()                : null; }
    public String getWorkloadTokenHash()  { return claims != null ? claims.workloadTokenHash()    : null; }
    public String getAccessTokenHash()    { return claims != null ? claims.accessTokenHash()      : null; }

    public boolean isExpired() { return claims != null && claims.isExpired(); }
    public boolean isValid()   { return claims != null && claims.isValid();   }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private Claims claims;
        private String signature;
        private String jwtString;

        public Builder claims(Claims claims)        { this.claims = claims;       return this; }
        public Builder signature(String signature)  { this.signature = signature; return this; }
        public Builder jwtString(String jwtString)  { this.jwtString = jwtString; return this; }

        public DpopToken build() {
            return new DpopToken(claims, signature, jwtString);
        }
    }

    /** Claims (Payload) for DPoP Proof (DPoP). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Claims(
            @JsonProperty("aud") String audience,
            @JsonProperty("exp") Date expirationTime,
            @JsonProperty("jti") String jwtId,
            @JsonProperty("wth") String workloadTokenHash,
            @JsonProperty("ath") String accessTokenHash) {

        public Claims {
            if (workloadTokenHash == null || workloadTokenHash.isEmpty()) {
                throw new IllegalStateException("workloadTokenHash (wth) is REQUIRED");
            }
        }

        public boolean isExpired() {
            return expirationTime != null && expirationTime.getTime() < System.currentTimeMillis();
        }

        public boolean isValid() {
            return expirationTime == null || System.currentTimeMillis() <= expirationTime.getTime();
        }

        public static ClaimsBuilder builder() { return new ClaimsBuilder(); }

        public static class ClaimsBuilder {
            private String audience;
            private Date expirationTime;
            private String jwtId;
            private String workloadTokenHash;
            private String accessTokenHash;

            public ClaimsBuilder audience(String audience)                   { this.audience = audience;                   return this; }
            public ClaimsBuilder expirationTime(Date expirationTime)         { this.expirationTime = expirationTime;       return this; }
            public ClaimsBuilder jwtId(String jwtId)                         { this.jwtId = jwtId;                         return this; }
            public ClaimsBuilder workloadTokenHash(String workloadTokenHash) { this.workloadTokenHash = workloadTokenHash; return this; }
            public ClaimsBuilder accessTokenHash(String accessTokenHash)     { this.accessTokenHash = accessTokenHash;     return this; }

            public Claims build() {
                return new Claims(audience, expirationTime, jwtId, workloadTokenHash, accessTokenHash);
            }
        }
    }
}
