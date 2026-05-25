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

/**
 * Outcome of validating a token (CT, DPoP, etc.). Sealed ADT — every instance is either {@link
 * Success} carrying the parsed token, or {@link Failure} carrying an error message. Callers must
 * pattern-match the sealed cases.
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
}
