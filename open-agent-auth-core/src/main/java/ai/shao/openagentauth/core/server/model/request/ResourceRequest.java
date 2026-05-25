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

    @JsonProperty("wit")
    private final String wit;

    @JsonProperty("wpt")
    private final String wpt;

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
            @JsonProperty("wit") String wit,
            @JsonProperty("wpt") String wpt,
            @JsonProperty("httpMethod") String httpMethod,
            @JsonProperty("httpUri") String httpUri,
            @JsonProperty("httpHeaders") Map<String, String> httpHeaders,
            @JsonProperty("httpBody") String httpBody
    ) {
        this.wit = wit;
        this.wpt = wpt;
        this.httpMethod = httpMethod;
        this.httpUri = httpUri;
        this.httpHeaders = httpHeaders;
        this.httpBody = httpBody;
    }

    public String getWit() { return wit; }
    public String getWpt() { return wpt; }
    public String getHttpMethod() { return httpMethod; }
    public String getHttpUri() { return httpUri; }
    public Map<String, String> getHttpHeaders() { return httpHeaders; }
    public String getHttpBody() { return httpBody; }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String wit;
        private String wpt;
        private String httpMethod;
        private String httpUri;
        private Map<String, String> httpHeaders;
        private String httpBody;

        public Builder wit(String wit) {
            this.wit = wit;
            return this;
        }

        public Builder wpt(String wpt) {
            this.wpt = wpt;
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
            return new ResourceRequest(wit, wpt, httpMethod, httpUri, httpHeaders, httpBody);
        }
    }
}
