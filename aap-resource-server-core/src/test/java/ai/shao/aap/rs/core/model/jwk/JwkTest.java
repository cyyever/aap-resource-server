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
package ai.shao.aap.rs.core.model.jwk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Jwk Tests")
class JwkTest {

    private static final String X_COORDINATE = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    private static final String KEY_ID = "key-123";

    @Test
    @DisplayName("Should build Jwk with x and keyId")
    void shouldBuildJwkWithAllFields() {
        Jwk jwk = Jwk.builder().x(X_COORDINATE).keyId(KEY_ID).build();

        assertThat(jwk).isNotNull();
        assertThat(jwk.x()).isEqualTo(X_COORDINATE);
        assertThat(jwk.keyId()).isEqualTo(KEY_ID);
    }

    @Test
    @DisplayName("Should build Jwk with only required x")
    void shouldBuildJwkWithOnlyRequiredX() {
        Jwk jwk = Jwk.builder().x(X_COORDINATE).build();

        assertThat(jwk).isNotNull();
        assertThat(jwk.x()).isEqualTo(X_COORDINATE);
        assertThat(jwk.keyId()).isNull();
    }

    @Test
    @DisplayName("Should throw when x is missing")
    void shouldThrowWhenXMissing() {
        assertThatThrownBy(() -> Jwk.builder().build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("x coordinate is REQUIRED");
    }

    @Test
    @DisplayName("Should throw when x is empty")
    void shouldThrowWhenXEmpty() {
        assertThatThrownBy(() -> Jwk.builder().x("").build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("x coordinate is REQUIRED");
    }

    @Test
    @DisplayName("Should throw when x is null")
    void shouldThrowWhenXNull() {
        assertThatThrownBy(() -> Jwk.builder().x((String) null).build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("x coordinate is REQUIRED");
    }
}
