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
package ai.shao.openagentauth.core.server.model.request;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResourceRequest {

    @JsonProperty("ct")
    private final String ct;

    @JsonProperty("dpop")
    private final String dpop;

    @JsonProperty("httpMethod")
    private final String httpMethod;

    @JsonProperty("httpUri")
    private final String httpUri;

    @JsonProperty("httpHeaders")
    private final Map<String, String> httpHeaders;

    @JsonProperty("httpBody")
    private final String httpBody;

    @JsonCreator
    public ResourceRequest(
            @JsonProperty("ct") String ct,
            @JsonProperty("dpop") String dpop,
            @JsonProperty("httpMethod") String httpMethod,
            @JsonProperty("httpUri") String httpUri,
            @JsonProperty("httpHeaders") Map<String, String> httpHeaders,
            @JsonProperty("httpBody") String httpBody
    ) {
        this.ct = ct;
        this.dpop = dpop;
        this.httpMethod = httpMethod;
        this.httpUri = httpUri;
        this.httpHeaders = httpHeaders;
        this.httpBody = httpBody;
    }

    public String getCt() { return ct; }
    public String getDpop() { return dpop; }
    public String getHttpMethod() { return httpMethod; }
    public String getHttpUri() { return httpUri; }
    public Map<String, String> getHttpHeaders() { return httpHeaders; }
    public String getHttpBody() { return httpBody; }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String ct;
        private String dpop;
        private String httpMethod;
        private String httpUri;
        private Map<String, String> httpHeaders;
        private String httpBody;

        public Builder ct(String ct) {
            this.ct = ct;
            return this;
        }

        public Builder dpop(String dpop) {
            this.dpop = dpop;
            return this;
        }

        public Builder httpMethod(String httpMethod) {
            this.httpMethod = httpMethod;
            return this;
        }

        public Builder httpUri(String httpUri) {
            this.httpUri = httpUri;
            return this;
        }

        public Builder httpHeaders(Map<String, String> httpHeaders) {
            this.httpHeaders = httpHeaders;
            return this;
        }

        public Builder httpBody(String httpBody) {
            this.httpBody = httpBody;
            return this;
        }

        public ResourceRequest build() {
            return new ResourceRequest(ct, dpop, httpMethod, httpUri, httpHeaders, httpBody);
        }
    }
}
