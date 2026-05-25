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
package ai.shao.aap.rs.core.server.exception.validation;

/** Exception thrown when request validation fails in framework orchestration layer. */
public class ServerValidationException extends ValidationException {

    /** The error code for this exception. */
    private static final ValidationErrorCode ERROR_CODE = ValidationErrorCode.VALIDATION_FAILED;

    /**
     * Constructs a new framework validation exception with the specified detail message.
     *
     * @param message the detail message
     */
    public ServerValidationException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Constructs a new framework validation exception with the specified detail message and failed
     * layer.
     *
     * @param failedLayer the layer where validation failed
     * @param message the detail message
     */
    public ServerValidationException(int failedLayer, String message) {
        super(failedLayer, ERROR_CODE, message);
    }

    /**
     * Constructs a new framework validation exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public ServerValidationException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }

    /**
     * Constructs a new framework validation exception with the specified detail message, failed
     * layer, and cause.
     *
     * @param failedLayer the layer where validation failed
     * @param message the detail message
     * @param cause the cause
     */
    public ServerValidationException(int failedLayer, String message, Throwable cause) {
        super(failedLayer, ERROR_CODE, cause, message);
    }
}
