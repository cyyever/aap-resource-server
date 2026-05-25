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
package ai.shao.aap.rs.core.server.model.validation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * Result of request validation: overall valid flag, per-layer breakdown, and the flat list of error
 * messages collected across all failed layers.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ValidationResult(
        @JsonProperty("valid") boolean valid,
        @JsonProperty("layerResults") @Nullable List<LayerResult> layerResults,
        @JsonProperty("errors") @Nullable List<String> errors) {

    @JsonCreator
    public ValidationResult {
        layerResults = layerResults == null ? null : List.copyOf(layerResults);
        errors = errors == null ? null : List.copyOf(errors);
    }

    /** Boolean-getter alias for {@link #valid()}, matching the existing API. */
    public boolean isValid() {
        return valid;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private boolean valid;
        private @Nullable List<LayerResult> layerResults;
        private @Nullable List<String> errors;

        public Builder valid(boolean valid) {
            this.valid = valid;
            return this;
        }

        public Builder layerResults(@Nullable List<LayerResult> layerResults) {
            this.layerResults = layerResults;
            return this;
        }

        public Builder errors(@Nullable List<String> errors) {
            this.errors = errors;
            return this;
        }

        public ValidationResult build() {
            return new ValidationResult(valid, layerResults, errors);
        }
    }

    /** Outcome of validating a single layer (CT, DPoP, etc.). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record LayerResult(
            @JsonProperty("layer") int layer,
            @JsonProperty("layerName") @Nullable String layerName,
            @JsonProperty("valid") boolean valid,
            @JsonProperty("message") @Nullable String message) {

        @JsonCreator
        public LayerResult {}

        /** Boolean-getter alias for {@link #valid()}, matching the existing API. */
        public boolean isValid() {
            return valid;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private int layer;
            private @Nullable String layerName;
            private boolean valid;
            private @Nullable String message;

            public Builder layer(int layer) {
                this.layer = layer;
                return this;
            }

            public Builder layerName(@Nullable String layerName) {
                this.layerName = layerName;
                return this;
            }

            public Builder valid(boolean valid) {
                this.valid = valid;
                return this;
            }

            public Builder message(@Nullable String message) {
                this.message = message;
                return this;
            }

            public LayerResult build() {
                return new LayerResult(layer, layerName, valid, message);
            }
        }
    }
}
