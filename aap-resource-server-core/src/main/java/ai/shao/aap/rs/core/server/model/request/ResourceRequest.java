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
package ai.shao.aap.rs.core.server.model.request;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;
import org.jspecify.annotations.Nullable;

@JsonInclude(JsonInclude.Include.NON_NULL)
public final class ResourceRequest {

    @JsonProperty("ct")
    private final String ct;

    @JsonProperty("dpop")
    private final String dpop;

    @JsonProperty("httpMethod")
    private final @Nullable String httpMethod;

    @JsonProperty("httpUri")
    private final @Nullable String httpUri;

    @JsonProperty("httpHeaders")
    private final @Nullable Map<String, String> httpHeaders;

    @JsonProperty("httpBody")
    private final @Nullable String httpBody;

    @JsonCreator
    public ResourceRequest(
            @JsonProperty("ct") @Nullable String ct,
            @JsonProperty("dpop") @Nullable String dpop,
            @JsonProperty("httpMethod") @Nullable String httpMethod,
            @JsonProperty("httpUri") @Nullable String httpUri,
            @JsonProperty("httpHeaders") @Nullable Map<String, String> httpHeaders,
            @JsonProperty("httpBody") @Nullable String httpBody) {
        if (ct == null || ct.isEmpty()) {
            throw new IllegalStateException("ct is REQUIRED");
        }
        if (dpop == null || dpop.isEmpty()) {
            throw new IllegalStateException("dpop is REQUIRED");
        }
        this.ct = ct;
        this.dpop = dpop;
        this.httpMethod = httpMethod;
        this.httpUri = httpUri;
        this.httpHeaders = httpHeaders == null ? null : Map.copyOf(httpHeaders);
        this.httpBody = httpBody;
    }

    public String getCt() {
        return ct;
    }

    public String getDpop() {
        return dpop;
    }

    public @Nullable String getHttpMethod() {
        return httpMethod;
    }

    public @Nullable String getHttpUri() {
        return httpUri;
    }

    public @Nullable Map<String, String> getHttpHeaders() {
        return httpHeaders;
    }

    public @Nullable String getHttpBody() {
        return httpBody;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private @Nullable String ct;
        private @Nullable String dpop;
        private @Nullable String httpMethod;
        private @Nullable String httpUri;
        private @Nullable Map<String, String> httpHeaders;
        private @Nullable String httpBody;

        public Builder ct(@Nullable String ct) {
            this.ct = ct;
            return this;
        }

        public Builder dpop(@Nullable String dpop) {
            this.dpop = dpop;
            return this;
        }

        public Builder httpMethod(@Nullable String httpMethod) {
            this.httpMethod = httpMethod;
            return this;
        }

        public Builder httpUri(@Nullable String httpUri) {
            this.httpUri = httpUri;
            return this;
        }

        public Builder httpHeaders(@Nullable Map<String, String> httpHeaders) {
            this.httpHeaders = httpHeaders;
            return this;
        }

        public Builder httpBody(@Nullable String httpBody) {
            this.httpBody = httpBody;
            return this;
        }

        public ResourceRequest build() {
            return new ResourceRequest(ct, dpop, httpMethod, httpUri, httpHeaders, httpBody);
        }
    }
}
