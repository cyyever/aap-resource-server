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

import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Root exception class for the project. Carries a structured error code, formatted message,
 * optional parameter list, and optional context map.
 */
public abstract class OpenAgentAuthException extends RuntimeException {

    /** The error code associated with this exception. */
    private final String errorCode;

    /** The error parameters used for message formatting. */
    private final @Nullable List<Object> errorParams;

    /** The context information associated with this exception. */
    private final @Nullable Map<String, Object> context;

    /** The formatted error message. */
    private final String formattedMessage;

    /**
     * Constructs a new Open Agent Auth exception with the specified error code and message.
     *
     * @param errorCode the error code
     * @param formattedMessage the formatted error message
     */
    protected OpenAgentAuthException(String errorCode, String formattedMessage) {
        super(formattedMessage);
        this.errorCode = errorCode;
        this.errorParams = null;
        this.context = null;
        this.formattedMessage = formattedMessage;
    }

    /**
     * Constructs a new Open Agent Auth exception with the specified error code, message, and cause.
     *
     * @param errorCode the error code
     * @param formattedMessage the formatted error message
     * @param cause the cause
     */
    protected OpenAgentAuthException(
            String errorCode, String formattedMessage, @Nullable Throwable cause) {
        super(formattedMessage, cause);
        this.errorCode = errorCode;
        this.errorParams = null;
        this.context = null;
        this.formattedMessage = formattedMessage;
    }

    /**
     * Constructs a new Open Agent Auth exception with the specified error code, message, error
     * parameters, and context.
     *
     * @param errorCode the error code
     * @param formattedMessage the formatted error message
     * @param errorParams the error parameters
     * @param context the context information
     */
    protected OpenAgentAuthException(
            String errorCode,
            String formattedMessage,
            @Nullable List<Object> errorParams,
            @Nullable Map<String, Object> context) {
        super(formattedMessage);
        this.errorCode = errorCode;
        this.errorParams = errorParams != null ? List.copyOf(errorParams) : null;
        this.context = context != null ? Map.copyOf(context) : null;
        this.formattedMessage = formattedMessage;
    }

    /**
     * Constructs a new Open Agent Auth exception with the specified error code, message, error
     * parameters, context, and cause.
     *
     * @param errorCode the error code
     * @param formattedMessage the formatted error message
     * @param errorParams the error parameters
     * @param context the context information
     * @param cause the cause
     */
    protected OpenAgentAuthException(
            String errorCode,
            String formattedMessage,
            @Nullable List<Object> errorParams,
            @Nullable Map<String, Object> context,
            @Nullable Throwable cause) {
        super(formattedMessage, cause);
        this.errorCode = errorCode;
        this.errorParams = errorParams != null ? List.copyOf(errorParams) : null;
        this.context = context != null ? Map.copyOf(context) : null;
        this.formattedMessage = formattedMessage;
    }

    /**
     * Gets the error code.
     *
     * @return the error code
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Gets the error parameters.
     *
     * @return the error parameters (unmodifiable list), or null if not set
     */
    public @Nullable List<Object> getErrorParams() {
        return errorParams;
    }

    /**
     * Gets the context information.
     *
     * @return the context information, or null if not set
     */
    public @Nullable Map<String, Object> getContext() {
        return context;
    }

    /**
     * Gets the formatted error message.
     *
     * @return the formatted error message
     */
    public String getFormattedMessage() {
        return formattedMessage;
    }

    // Override toString to surface the structured errorCode in logs and stack
    // traces alongside the formatted message. getMessage() still returns the
    // bare formatted message (set on the Throwable via super(formattedMessage))
    // for callers that want only the human text.
    @SuppressWarnings("OverrideThrowableToString")
    @Override
    public String toString() {
        return this.getClass().getSimpleName()
                + "{"
                + "errorCode='"
                + errorCode
                + '\''
                + ", formattedMessage='"
                + formattedMessage
                + '\''
                + '}';
    }
}
