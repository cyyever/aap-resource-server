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
package ai.shao.aap.rs.core.exception.crypto;

import ai.shao.aap.rs.core.crypto.key.resolve.KeyResolver;

/**
 * Exception thrown when a key resolution operation fails.
 *
 * <p>This exception indicates that a {@link KeyResolver} was unable to resolve a cryptographic key
 * from its configured source. Common causes include:
 *
 * <ul>
 *   <li>Key not found in the local key store
 *   <li>Remote JWKS endpoint unreachable or returned an error
 *   <li>Key ID not found in the JWKS response
 *   <li>No {@code KeyResolver} supports the given key definition
 *   <li>Key type mismatch (e.g., expected EC key but found RSA key)
 * </ul>
 *
 * @see KeyResolver
 */
public final class KeyResolutionException extends CryptoException {

    private static final CryptoErrorCode ERROR_CODE = CryptoErrorCode.KEY_RESOLUTION_FAILED;

    /**
     * Constructs a new key resolution exception with the specified detail message.
     *
     * @param message the detail message
     */
    public KeyResolutionException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Constructs a new key resolution exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public KeyResolutionException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }
}
