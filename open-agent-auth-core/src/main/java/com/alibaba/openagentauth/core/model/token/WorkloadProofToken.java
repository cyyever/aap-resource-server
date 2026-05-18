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
package com.alibaba.openagentauth.core.model.token;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;
import java.util.Map;

/**
 * Represents a Workload Proof Token (WPT). A WPT is a JWT that proves possession
 * of the private key corresponding to the public key in the associated Workload
 * Identity Token (WIT). It binds to the WIT via the {@code wth} claim and optionally
 * to other tokens via {@code oth}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record WorkloadProofToken(
        Header header,
        Claims claims,
        @JsonProperty("signature") String signature,
        @JsonProperty("jwtString") String jwtString) {

    public WorkloadProofToken {
        if (header == null) {
            throw new IllegalStateException("header is REQUIRED for WPT");
        }
        if (claims == null) {
            throw new IllegalStateException("claims is REQUIRED for WPT");
        }
    }

    /** Audience (aud) — convenience delegate to claims. */
    public String getAudience()           { return claims != null ? claims.audience()             : null; }
    public Date   getExpirationTime()     { return claims != null ? claims.expirationTime()       : null; }
    public String getJwtId()              { return claims != null ? claims.jwtId()                : null; }
    public String getWorkloadTokenHash()  { return claims != null ? claims.workloadTokenHash()    : null; }
    public String getAccessTokenHash()    { return claims != null ? claims.accessTokenHash()      : null; }
    public Map<String, String> getOtherTokenHashes() { return claims != null ? claims.otherTokenHashes() : null; }

    public boolean isExpired() { return claims != null && claims.isExpired(); }
    public boolean isValid()   { return claims != null && claims.isValid();   }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private Header header;
        private Claims claims;
        private String signature;
        private String jwtString;

        public Builder header(Header header)        { this.header = header;       return this; }
        public Builder claims(Claims claims)        { this.claims = claims;       return this; }
        public Builder signature(String signature)  { this.signature = signature; return this; }
        public Builder jwtString(String jwtString)  { this.jwtString = jwtString; return this; }

        public WorkloadProofToken build() {
            return new WorkloadProofToken(header, claims, signature, jwtString);
        }
    }

    /** Claims (Payload) for Workload Proof Token (WPT). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Claims(
            @JsonProperty("aud") String audience,
            @JsonProperty("exp") Date expirationTime,
            @JsonProperty("jti") String jwtId,
            @JsonProperty("wth") String workloadTokenHash,
            @JsonProperty("ath") String accessTokenHash,
            @JsonProperty("oth") Map<String, String> otherTokenHashes) {

        public Claims {
            if (workloadTokenHash == null || workloadTokenHash.isEmpty()) {
                throw new IllegalStateException("workloadTokenHash (wth) is REQUIRED");
            }
        }

        public boolean isExpired() {
            return expirationTime != null && expirationTime.before(new Date());
        }

        public boolean isValid() {
            return expirationTime == null || !new Date().after(expirationTime);
        }

        public static ClaimsBuilder builder() { return new ClaimsBuilder(); }

        public static class ClaimsBuilder {
            private String audience;
            private Date expirationTime;
            private String jwtId;
            private String workloadTokenHash;
            private String accessTokenHash;
            private Map<String, String> otherTokenHashes;

            public ClaimsBuilder audience(String audience)                              { this.audience = audience;                       return this; }
            public ClaimsBuilder expirationTime(Date expirationTime)                    { this.expirationTime = expirationTime;           return this; }
            public ClaimsBuilder jwtId(String jwtId)                                    { this.jwtId = jwtId;                             return this; }
            public ClaimsBuilder workloadTokenHash(String workloadTokenHash)            { this.workloadTokenHash = workloadTokenHash;     return this; }
            public ClaimsBuilder accessTokenHash(String accessTokenHash)                { this.accessTokenHash = accessTokenHash;         return this; }
            public ClaimsBuilder otherTokenHashes(Map<String, String> otherTokenHashes) { this.otherTokenHashes = otherTokenHashes;       return this; }

            public Claims build() {
                return new Claims(audience, expirationTime, jwtId, workloadTokenHash,
                        accessTokenHash, otherTokenHashes);
            }
        }
    }

    /** JOSE Header for Workload Proof Token (WPT). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Header(
            @JsonProperty("typ") String type,
            @JsonProperty("alg") String algorithm) {

        public static final String MEDIA_TYPE = "wpt+jwt";

        public Header {
            if (ValidationUtils.isNullOrEmpty(type)) {
                throw new IllegalStateException("type (typ) is REQUIRED and should be 'wpt+jwt'");
            }
            if (ValidationUtils.isNullOrEmpty(algorithm)) {
                throw new IllegalStateException("algorithm (alg) is REQUIRED");
            }
        }

        public static HeaderBuilder builder() { return new HeaderBuilder(); }

        public static class HeaderBuilder {
            private String type = MEDIA_TYPE;
            private String algorithm;

            public HeaderBuilder type(String type)           { this.type = type;           return this; }
            public HeaderBuilder algorithm(String algorithm) { this.algorithm = algorithm; return this; }

            public Header build() {
                return new Header(type, algorithm);
            }
        }
    }
}
