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
package ai.shao.aap.rs.core.token.common;

import org.jspecify.annotations.Nullable;

/**
 * Outcome of validating a token (CT, DPoP, etc.). Sealed ADT — every instance is either {@link
 * Success} carrying the parsed token, or {@link Failure} carrying an error message. Callers should
 * pattern-match the sealed cases rather than rely on the legacy getters, which return null on the
 * wrong arm.
 *
 * @param <T> the type of token being validated
 */
public sealed interface TokenValidationResult<T> {

    record Success<T>(T token) implements TokenValidationResult<T> {}

    record Failure<T>(String errorMessage) implements TokenValidationResult<T> {}

    static <T> TokenValidationResult<T> success(T token) {
        return new Success<>(token);
    }

    static <T> TokenValidationResult<T> failure(String errorMessage) {
        return new Failure<>(errorMessage);
    }

    default boolean isValid() {
        return this instanceof Success<T>;
    }

    /**
     * Legacy accessor. Returns the parsed token on {@link Success}, null on {@link Failure}. Prefer
     * pattern-matching the sealed cases.
     */
    default @Nullable T getToken() {
        return this instanceof Success<T>(T tok) ? tok : null;
    }

    /**
     * Legacy accessor. Returns the error message on {@link Failure}, null on {@link Success}.
     * Prefer pattern-matching the sealed cases.
     */
    default @Nullable String getErrorMessage() {
        return this instanceof Failure<T>(String msg) ? msg : null;
    }
}
