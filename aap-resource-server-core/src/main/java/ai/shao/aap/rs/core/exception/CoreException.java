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
package ai.shao.aap.rs.core.exception;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Base exception for all Core module exceptions. Error code format: {@code OPEN_AGENT_AUTH_10_YYZZ}
 * (system 10, YY=domain, ZZ=error).
 */
public abstract class CoreException extends OpenAgentAuthException {

    /**
     * Constructs a new Core exception with the specified error code.
     *
     * @param errorCode the error code
     */
    protected CoreException(ErrorCode errorCode) {
        super(errorCode.getErrorCode(), errorCode.getMessageTemplate());
    }

    /**
     * Constructs a new Core exception with the specified error code and parameters.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected CoreException(ErrorCode errorCode, Object... errorParams) {
        super(
                errorCode.getErrorCode(),
                errorCode.formatMessage(errorParams),
                Arrays.asList(errorParams),
                null);
    }

    /**
     * Constructs a new Core exception with the specified error code, parameters, and context.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     * @param context the context information
     */
    protected CoreException(
            ErrorCode errorCode,
            @Nullable List<Object> errorParams,
            @Nullable Map<String, Object> context) {
        super(
                errorCode.getErrorCode(),
                errorCode.formatMessage(errorParams != null ? errorParams.toArray() : null),
                errorParams,
                context);
    }

    /**
     * Constructs a new Core exception with the specified error code and cause.
     *
     * @param errorCode the error code
     * @param cause the cause
     */
    protected CoreException(ErrorCode errorCode, Throwable cause) {
        super(errorCode.getErrorCode(), errorCode.getMessageTemplate(), cause);
    }

    /**
     * Constructs a new Core exception with the specified error code, parameters, and cause.
     *
     * @param errorCode the error code
     * @param cause the cause
     * @param errorParams the error parameters (varargs)
     */
    protected CoreException(ErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(
                errorCode.getErrorCode(),
                errorCode.formatMessage(errorParams),
                Arrays.asList(errorParams),
                null,
                cause);
    }

    /**
     * Constructs a new Core exception with the specified error code, parameters, context, and
     * cause.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     * @param context the context information
     * @param cause the cause
     */
    protected CoreException(
            ErrorCode errorCode,
            @Nullable List<Object> errorParams,
            @Nullable Map<String, Object> context,
            @Nullable Throwable cause) {
        super(
                errorCode.getErrorCode(),
                errorCode.formatMessage(errorParams != null ? errorParams.toArray() : null),
                errorParams,
                context,
                cause);
    }
}
