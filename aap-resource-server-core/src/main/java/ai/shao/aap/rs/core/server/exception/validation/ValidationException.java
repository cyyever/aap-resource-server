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

import ai.shao.aap.rs.core.server.exception.ServerException;

/** Base exception for all Validation domain exceptions. */
public abstract class ValidationException extends ServerException {

    /** The layer where validation failed. */
    private final int failedLayer;

    /**
     * Constructs a new Validation exception with the specified error code and parameters.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected ValidationException(ValidationErrorCode errorCode, Object... errorParams) {
        this(0, errorCode, errorParams);
    }

    /**
     * Constructs a new Validation exception with the specified error code, failed layer, and
     * parameters.
     *
     * @param failedLayer the layer where validation failed
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected ValidationException(
            int failedLayer, ValidationErrorCode errorCode, Object... errorParams) {
        super(errorCode, errorParams);
        this.failedLayer = failedLayer;
    }

    /**
     * Constructs a new Validation exception with the specified error code, cause, and parameters.
     *
     * @param errorCode the error code
     * @param cause the cause
     * @param errorParams the error parameters (varargs)
     */
    protected ValidationException(
            ValidationErrorCode errorCode, Throwable cause, Object... errorParams) {
        this(0, errorCode, cause, errorParams);
    }

    /**
     * Constructs a new Validation exception with the specified error code, cause, failed layer, and
     * parameters.
     *
     * @param failedLayer the layer where validation failed
     * @param errorCode the error code
     * @param cause the cause
     * @param errorParams the error parameters (varargs)
     */
    protected ValidationException(
            int failedLayer,
            ValidationErrorCode errorCode,
            Throwable cause,
            Object... errorParams) {
        super(errorCode, cause, errorParams);
        this.failedLayer = failedLayer;
    }

    /**
     * Gets the layer where validation failed.
     *
     * @return the failed layer
     */
    public int getFailedLayer() {
        return failedLayer;
    }
}
