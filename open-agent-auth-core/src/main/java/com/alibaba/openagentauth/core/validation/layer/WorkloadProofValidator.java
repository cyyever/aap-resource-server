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
package com.alibaba.openagentauth.core.validation.layer;

import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.token.common.JwtHashUtil;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.validation.api.LayerValidator;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.nimbusds.jose.JOSEException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Validator for Workload Proof Token (WPT) verification.
 * Delegates to {@link WptValidator} for signature, expiration, claims, algorithm
 * consistency, wth, and oth checks.
 *
 * @see ValidationContext
 * @see LayerValidationResult
 * @see WorkloadProofToken
 * @see WorkloadIdentityToken
 * @since 1.0
 */
public class WorkloadProofValidator implements LayerValidator {

    /**
     * The logger for workload proof validator.
     */
    private static final Logger logger = LoggerFactory.getLogger(WorkloadProofValidator.class);

    /**
     * The delegated WPT validator.
     */
    private final WptValidator wptValidator;

    /**
     * Creates a new workload proof validator.
     *
     * @param wptValidator the WPT validator to delegate to
     * @throws IllegalArgumentException if wptValidator is null
     */
    public WorkloadProofValidator(WptValidator wptValidator) {
        ValidationUtils.validateNotNull(wptValidator, "WptValidator");
        this.wptValidator = wptValidator;
    }

    @Override
    public LayerValidationResult validate(ValidationContext context) {
        logger.debug("Starting Layer 2: Workload Proof validation");

        // Check if WPT is present
        if (context.getWpt() == null) {
            logger.error("WPT is missing from validation context");
            return LayerValidationResult.failure(
                "WPT is required but not present in the validation context"
            );
        }

        // Check if WIT is present (needed for verification)
        if (context.getWit() == null) {
            logger.error("WIT is missing from validation context, required for WPT verification");
            return LayerValidationResult.failure(
                "WIT is required for WPT verification but not present in the validation context"
            );
        }

        WorkloadProofToken wpt = context.getWpt();
        WorkloadIdentityToken wit = context.getWit();

        try {
            // Delegate to the existing WptValidator
            var result = wptValidator.validate(wpt, wit);
            
            if (!result.isValid()) {
                logger.error("Layer 2: Workload Proof validation failed: {}", result.getErrorMessage());
                return LayerValidationResult.failure(
                    result.getErrorMessage(),
                    "Layer 2 WPT Validation"
                );
            }

            // After WPT validation, verify the oth claim hashes if present
            String othValidationError = verifyOthClaimHashes(wpt, context);
            if (othValidationError != null) {
                logger.error("Layer 2: WPT oth claim hash validation failed: {}", othValidationError);
                return LayerValidationResult.failure(
                    othValidationError,
                    "Layer 2 WPT oth Validation"
                );
            }
            
            logger.debug("Layer 2: Workload Proof validation passed successfully");
            return LayerValidationResult.success("Layer 2: WPT validation completed successfully");
            
        } catch (Exception e) {
            logger.error("Error validating WPT", e);
            return LayerValidationResult.failure(
                "WPT validation failed: " + e.getMessage(),
                "Layer 2 WPT Validation"
            );
        }
    }

    /**
     * Verifies the oth (other tokens hashes) claim in the WPT.
     *
     * @param wpt the WorkloadProofToken
     * @param context the validation context containing the actual tokens
     * @return error message if validation fails, null if valid
     */
    private String verifyOthClaimHashes(WorkloadProofToken wpt, ValidationContext context) {
        try {
            // Check if oth claim is present
            Map<String, String> otherTokenHashes = wpt.claims().otherTokenHashes();
            if (otherTokenHashes == null || otherTokenHashes.isEmpty()) {
                logger.debug("WPT does not contain oth claim, skipping hash verification");
                return null;
            }

            logger.debug("Verifying WPT oth claim hashes for {} token types", otherTokenHashes.size());

            // Validate each token type in oth claim
            for (Map.Entry<String, String> entry : otherTokenHashes.entrySet()) {
                String tokenType = entry.getKey();
                String expectedHash = entry.getValue();

                String validationError = verifyTokenHash(tokenType, expectedHash, context);
                if (validationError != null) {
                    return validationError;
                }
            }

            logger.debug("All oth claim hashes verified successfully");
            return null;

        } catch (Exception e) {
            logger.error("Error verifying oth claim hashes", e);
            return "Error verifying oth claim hashes: " + e.getMessage();
        }
    }

    /**
     * Verifies the hash for a specific token type.
     *
     * @param tokenType the token type identifier
     * @param expectedHash the expected hash value from the oth claim
     * @param context the validation context containing the actual tokens
     * @return error message if validation fails, null if valid
     */
    private String verifyTokenHash(String tokenType, String expectedHash, ValidationContext context) {
        logger.warn("Unexpected token type in oth claim: {}", tokenType);
        return "Unexpected token type in oth claim: '%s'".formatted(tokenType);
    }

    @Override
    public String getName() {
        return "Layer 2: Workload Proof Validator";
    }

    @Override
    public double getOrder() {
        return 2.0;
    }
}